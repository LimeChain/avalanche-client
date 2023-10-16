# avalanche-client
A client for avalanche based on [avalanche-rs](https://github.com/ava-labs/avalanche-rs)

## Running Locally
To run the client locally, change the first mainnet in `genesis/bootstrappers.json` to have the localhost address `127.0.0.1:9651`, you can then run `cargo run` to run it in debug mode.

You will also most likely want a node running locally as well, you can use the instructions provided in `https://github.com/ava-labs/avalanchego` README to do so.