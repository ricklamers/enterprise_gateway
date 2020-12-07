import IJulia
import JSON
import Base64
import Sockets

using IJulia.InteractiveUtils
using ArgParse
using AES

ENV["EG_MIN_PORT_RANGE_SIZE"] = get(ENV, "EG_MIN_PORT_RANGE_SIZE", 1000)
EG_MIN_PORT_RANGE_SIZE = parse(Int, ENV["EG_MIN_PORT_RANGE_SIZE"])

# workaround #60:
if Sys.isapple()
    ENV["PATH"] = Sys.BINDIR*":"*ENV["PATH"]
end

function encrypt(json, connection_file)
    raw_payload = [UInt8(c) for c in rpad(json, (length(json) ÷ 16 + 1) * 16, "%")]
    println("Raw Payload: $(raw_payload)")

    connection_file_basename = basename(connection_file)
    tokens = split(connection_file_basename, "kernel-")[2][1:16]
    key = [UInt8(c) for c in tokens]
    
    encrypted_payload = AESECB(raw_payload, key, true)
    encoded_payload = Base64.base64encode(encrypted_payload)

    return encoded_payload
end

function read_json(file_path)
    open(file_path, "r") do f
        global sendme
        return JSON.parse(read(f, String))
    end
end

function return_connection_info(connection_file, response_addr)
    response_parts = split(response_addr, ":")

    if length(response_parts) != 2
        println("Invalid format for response address.")
        exit(1)
    end

    response_ip = response_parts[1]
    response_port = parse(Int, response_parts[2])

    sendme = read_json(connection_file)
    sendme["pid"] = getpid()

    json = JSON.json(sendme)
    println("JSON Payload: $(json)")
    
    connection_file_basename = basename(connection_file)
    if !startswith(connection_file_basename, "kernel-")
        println("Invalid connection file name: $(connection_file)")
        exit(1)
    end

    payload = encrypt(json, connection_file)
    println("Encrypted Payload: $(payload)")

    con = nothing
    try
        con = Sockets.connect(response_ip, response_port)
        write(con, string(payload, "\n"))
        Sockets.close(con)
    catch error
        println("Unable to connect to response address $(response_addr)")
        println("Here's the original error message:")
        println(error)

        # make sure connection is closed
        if Sockets.isopen(con)
            Sockets.close(con)
        end
    end
end

function validate_port_range(port_range)
    if !occursin("..", port_range)
        println("Port range should contain `..` separation character.")
        exit(1)
    end

    port_ranges = split(port_range, "..")
    lower_port = parse(Int, port_ranges[1])
    upper_port = parse(Int, port_ranges[2])

    port_range_size = upper_port - lower_port
    if port_range_size < EG_MIN_PORT_RANGE_SIZE
        println("Port range validation failed for range: $(port_range). Range size must be at least $(EG_MIN_PORT_RANGE_SIZE) as specified by env EG_MIN_PORT_RANGE_SIZE.")
        exit(1)
    end

    return lower_port, upper_port
end

function determine_connection_file(kernel_id)
    base_file = "kernel-$(kernel_id)"
    tmp_dir, tmp_base = splitdir(tempname())
    temp_file = joinpath(tmp_dir, string(base_file, tmp_base, ".json"))
    println("Using connection file '$(temp_file)'")
    return temp_file
end

function parse_commandline()
    s = ArgParseSettings(description = "Parse Arguments for Julia Launcher")

    @add_arg_table s begin
        
        "--RemoteProcessProxy.kernel-id"
            help = "the id associated with the launched kernel"
            arg_type = String
            nargs = '?'
        "--RemoteProcessProxy.port-range"
            arg_type = String
            help = "the range of ports impose for kernel ports"
            nargs = '?'
            metavar = "<lowerPort>..<upperPort>"
        "--RemoteProcessProxy.response-address"
            arg_type = String
            metavar = "<ip>:<port>"
            nargs = '?'
            help = "the IP:port address of the system hosting Enterprise Gateway and expecting response"
        "connection_file"
            arg_type = String
            help = "Connection file to write connection info"
    end

    return parse_args(s)
end

function get_connection_file()

    if isnothing(parsed_args["connection_file"]) && isnothing(parsed_args["RemoteProcessProxy.kernel-id"])
        println("At least one of the parameters: 'connection_file' or '--RemoteProcessProxy.kernel-id' must be provided!")
        exit(1)
    end

    connection_file = determine_connection_file(parsed_args["RemoteProcessProxy.kernel-id"])

    lower_port = 0
    upper_port = 0
    if !isnothing(parsed_args["RemoteProcessProxy.port-range"])
        lower_port, upper_port = validate_port_range(parsed_args["RemoteProcessProxy.port-range"])
    end

    listener_file = joinpath(@__DIR__, "gateway_listener.py")
    pid = getpid()

    python_code = "import os, sys, imp; gl = imp.load_source('setup_gateway_listener', '$(listener_file)'); gl.setup_gateway_listener(fname='$(connection_file)', parent_pid='$(pid)', lower_port=$(lower_port), upper_port=$(upper_port))"

    python_command = `python3 -c $(python_code)`

    run(python_command, wait=false)

    while !isfile(connection_file)
        println("Waiting for Python process to write $(connection_file).")
        sleep(0.5)
    end

    return_connection_info(connection_file, parsed_args["RemoteProcessProxy.response-address"])

    return connection_file
end


# the size of truncated output to show should not depend on the terminal
# where the kernel is launched, since the display is elsewhere
ENV["LINES"] = get(ENV, "LINES", 30)
ENV["COLUMNS"] = get(ENV, "COLUMNS", 80)

parsed_args = parse_commandline()

connection_file = get_connection_file()

IJulia.init([connection_file])

# import things that we want visible in IJulia but not in REPL's using IJulia
import IJulia: ans, In, Out, clear_history

pushdisplay(IJulia.InlineDisplay())

ccall(:jl_exit_on_sigint, Cvoid, (Cint,), 0)

println(IJulia.orig_stdout[], "Starting kernel event loops.")
IJulia.watch_stdio()

# workaround JuliaLang/julia#4259
delete!(task_local_storage(),:SOURCE_PATH)

# workaround JuliaLang/julia#6765
Core.eval(Base, :(is_interactive = true))

# check whether Revise is running and as needed configure it to run before every prompt
if isdefined(Main, :Revise)
    let mode = get(ENV, "JULIA_REVISE", "auto")
        mode == "auto" && IJulia.push_preexecute_hook(Main.Revise.revise)
    end
end

IJulia.waitloop()

# Only unlink the connection file if we're launched for remote behavior.
if isnothing(parsed_args["RemoteProcessProxy.response-address"])
    rm(connection_file)
end