<h1 align="center">
pcap-tools
</h1>

<div align="center">
Tools for PCAP files with TS streams 
</div>

<div align="center">
<br />

![Test](https://github.com/Eyevinn/mp2ts-tools/workflows/Go/badge.svg)
[![golangci-lint](https://github.com/Eyevinn/mp2ts-tools/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/Eyevinn/mp2ts-tools/actions/workflows/golangci-lint.yml)
[![GoDoc](https://godoc.org/github.com/Eyevinn/mp2ts-tools?status.svg)](http://godoc.org/github.com/Eyevinn/mp2ts-tools)
[![Go Report Card](https://goreportcard.com/badge/github.com/Eyevinn/mp2ts-tools)](https://goreportcard.com/report/github.com/Eyevinn/mp2ts-tools)
[![github release](https://img.shields.io/github/v/release/Eyevinn/pcap-tools?style=flat-square)](https://github.com/Eyevinn/pcap-tools/releases)
[![license](https://img.shields.io/github/license/eyevinn/pcap-tools.svg?style=flat-square)](LICENSE)

[![PRs welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg?style=flat-square)](https://github.com/eyevinn/pcap-tools/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
[![made with heart by Eyevinn](https://img.shields.io/badge/made%20with%20%E2%99%A5%20by-Eyevinn-59cbe8.svg?style=flat-square)](https://github.com/eyevinn)
[![Slack](http://slack.streamingtech.se/badge.svg)](http://slack.streamingtech.se)

</div>

Tools for investigating and reusing tcpdump/Wireshark captures of TS streams.

The tools available this far are:

* pcap-replay

## Requirements

This project uses Go version 1.22 or later.

## Installation / Usage


Use the `Makefile`  to get build artifacts into the out directory,
or use the standard go build steps:

```sh
go mod tidy
cd cmd/pcap-replay
go run .
```

## Development

Uses standard Go tool chain.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md)

## License

This project is licensed under the MIT License, see [LICENSE](LICENSE).

# Support

Join our [community on Slack](http://slack.streamingtech.se) where you can post any questions regarding any of our open source projects. Eyevinn's consulting business can also offer you:

* Further development of this component
* Customization and integration of this component into your platform
* Support and maintenance agreement

Contact [sales@eyevinn.se](mailto:sales@eyevinn.se) if you are interested.

# About Eyevinn Technology

[Eyevinn Technology](https://www.eyevinntechnology.se) is an independent consultant firm specialized in video and streaming. Independent in a way that we are not commercially tied to any platform or technology vendor. As our way to innovate and push the industry forward we develop proof-of-concepts and tools. The things we learn and the code we write we share with the industry in [blogs](https://dev.to/video) and by open sourcing the code we have written.

Want to know more about Eyevinn and how it is to work here. Contact us at work@eyevinn.se!
