# Hyper Proxy 🌐

A secure, performant, and observable HTTPs proxy server, designed for configurability and high performance.

## Key Features 🚀

- HTTPs Forwarding: Seamless integration with any HTTP based service, just proxy requests through Hyper and instantly gain observability.
- Observability: Metadata and metrics are tracked at the request level: Origin, Latency, Attribution, Round Trip Times and Bytes Transferred.
- Attribution: Request attribution is possible by allowing any string to be used as the username, this can then be logged or stored for analytics (IE tracking usage of an external service by tenant in a multitenant application)
- Non-Intrusive: Hyper uses the CONNECT method, establishing a secure tunnel between the client and server. It sees the start and end of the connections but not the actual data, ensuring your sensitive information remains private.
- Authentication: Requests through the proxy require basic auth and can be limited by number of requests and various rate limiting strategies.

⚡
Hyper Proxy focuses on performance, security, and observability, making it an ideal choice for developers looking to monitor their network traffic without compromising on data privacy or speed. Whether you're debugging a complex issue or simply want more visibility into your APIs.

## Getting Started 🏁

To begin with Hyper Proxy, follow the steps below:

```
# Clone the repository
https://github.com/elie-h/hyper-proxy
# Navigate into the repository
cd hyper-proxy
# Install dependencies and run the app
go get .
go run main.go
```

### Join Us 🤝

Contributions are welcome.

### License ⚖️

Hyper Proxy is released under the MIT license. See the LICENSE file for more information.

### Reach Out 💌

If you have questions or need further information, feel free to get in touch in the discussions section.
