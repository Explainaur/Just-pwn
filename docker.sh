name=pwn

# docker run -d \
	# --rm \
	# -h ${name} \
	# --name ${name} \
	# -v $(pwd)/${name}:/ctf/work \
	# -p 23946:23946 \
	# --cap-add=SYS_PTRACE \
	# skysider/pwndocker

docker exec -it ${name} /bin/zsh
