.PHONY: build

build:
	  @echo "Building sbom binary"
	  @go build -o sbom
	  @test -f sbom || echo "Failed to build the SBOM binary"
	  @echo "Succesfully built the SBOM binary"