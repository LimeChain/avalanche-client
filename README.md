# avalanche-client
A client for avalanche based on [avalanche-rs](https://github.com/ava-labs/avalanche-rs)

## Running Locally
To run the client locally, you'll need to have a local node running. You can see how to run such a node [here](https://github.com/ava-labs/avalanchego). Note that the README requires you to have go version 1.20.8 or higher but it actually doesn't work with 1.20.8 and with 1.21.x so your version needs to be: 1.20.10 <= GO_VERSION < 1.21.0 

Change the first mainnet in `genesis/bootstrappers.json` to have the localhost address `127.0.0.1:9651`, you can then run `cargo run` to run it in debug mode.
