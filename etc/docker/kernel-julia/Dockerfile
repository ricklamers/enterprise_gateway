ARG BASE_CONTAINER=jupyter/datascience-notebook:julia-1.5.3
FROM $BASE_CONTAINER

# Switch back to root to modify ownerships
USER root

# Install Julia launch_juliakernel.jl dependencies
RUN julia -e "using Pkg; pkg\"add IJulia\"; pkg\"precompile\"" && \
julia -e "using Pkg; pkg\"add JSON\"; pkg\"precompile\"" && \
julia -e "using Pkg; pkg\"add ArgParse\"; pkg\"precompile\"" && \
julia -e "using Pkg; pkg\"add https://github.com/faf0/AES.jl\"; pkg\"precompile\"" && \
fix-permissions "${JULIA_PKGDIR}"

ADD jupyter_enterprise_gateway_kernel_image_files*.tar.gz /usr/local/bin/

RUN chown jovyan:users /usr/local/bin/bootstrap-kernel.sh && \
	chmod 0755 /usr/local/bin/bootstrap-kernel.sh && \
	chown -R jovyan:users /usr/local/bin/kernel-launchers

USER jovyan
ENV KERNEL_LANGUAGE julia
CMD /usr/local/bin/bootstrap-kernel.sh

