name=pwn

# docker run -d \
    # -h ${name} \
    # --name ${name} \
    # -v $(pwd)/${name}:/ctf/work \
    # -p 23946:23946 \
    # --cap-add=SYS_PTRACE \
    # -v /Users/dyf/code/solo/May:/May \
    # skysider/pwndocker

docker exec -it ${name} /bin/bash
