on: [push, pull_request]

name: Go
jobs:

  test:
    strategy:
      matrix:
        # TODO: use .x once the setup-go action doesn't run into unauthenticated
        # rate limits. See: https://github.com/actions/setup-go/issues/16
        go-version: [1.12.10, 1.13.1]
        platform: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.platform }}
    steps:
    - name: Install Go
      uses: actions/setup-go@v1
      with:
        go-version: ${{ matrix.go-version }}
    - name: Checkout code
      uses: actions/checkout@v1
    - name: Download Go dependencies
      env:
        GOPROXY: "https://proxy.golang.org"
      run: go mod download
    - name: Test
      run: go test -count=1 ./...
    - name: Test with -race
      run: go test -race -count=1 ./...

    - name: gofmt check
      run: diff <(echo -n) <(gofmt -d .)
      if: matrix.platform == 'ubuntu-latest'
