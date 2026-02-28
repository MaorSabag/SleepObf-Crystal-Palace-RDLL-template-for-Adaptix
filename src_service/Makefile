all: clean
	@ echo "    * Building stealthpalace plugin"
	@ mkdir dist
	@ cp config.yaml ax_config.axs ./dist/
	@ go mod tidy
	@ GOEXPERIMENT=jsonv2,greenteagc go build -buildmode=plugin -ldflags="-s -w" -o ./dist/stealthpalace.so pl_main.go pl_agent.go
	@ echo "      done..."

clean:
	@ rm -rf dist