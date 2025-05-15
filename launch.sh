!#/bin/bash

# 1. Builder chaque image
faas-cli build -f stack.yml

# 2. Pusher sur DockerHub
faas-cli push -f stack.yml

# 3. Déployer sur ton cluster
faas-cli deploy -f stack.yml