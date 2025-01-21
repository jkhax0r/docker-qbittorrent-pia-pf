import http.server
import ssl
import argparse
import sys
import os

# Define the handler for HTTP requests
class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, directory=None, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)  # Pass the directory to the parent class

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Simple HTTP/HTTPS Server")
    parser.add_argument("--cert", help="Path to the SSL certificate file (for HTTPS)")  # Certificate file for HTTPS
    parser.add_argument("--key", help="Path to the SSL private key file (for HTTPS)")   # Private key file for HTTPS
    parser.add_argument("--host", default="localhost", help="Hostname to bind the server (default: localhost)")  # Server hostname
    parser.add_argument("--port", type=int, default=8080, help="Port to bind the server (default: 8080 for HTTP, 4443 for HTTPS)")  # Server port
    parser.add_argument("--dir", default=os.getcwd(), help="Directory to serve files from (default: current working directory)")  # Directory to serve
    args = parser.parse_args()

    # Determine if running in HTTP or HTTPS mode
    is_https = args.cert and args.key  # HTTPS if both cert and key are provided
    port = args.port if args.port != 8080 else (4443 if is_https else 8080)  # Default port: 8080 for HTTP, 4443 for HTTPS
    server_address = (args.host, port)  # Host and port configuration

    # Ensure the directory exists
    if not os.path.isdir(args.dir):
        print(f"Error: The directory '{args.dir}' does not exist.")
        sys.exit(1)

    try:
        # Set up the server
        handler = lambda *handler_args, **handler_kwargs: SimpleHTTPRequestHandler(*handler_args, directory=args.dir, **handler_kwargs)  # Pass directory explicitly
        httpd = http.server.HTTPServer(server_address, handler)  # HTTP server setup

        if is_https:
            # Set up SSL context for HTTPS
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # Use TLS
            ssl_context.load_cert_chain(certfile=args.cert, keyfile=args.key)  # Load cert and key
            httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)  # Wrap socket with SSL
            print(f"Serving HTTPS on https://{args.host}:{port}, serving files from {args.dir}")  # Notify HTTPS mode
        else:
            print(f"Serving HTTP on http://{args.host}:{port}, serving files from {args.dir}")  # Notify HTTP mode

        httpd.serve_forever()  # Start the server

    except OSError as e:
        # Handle port in use error
        if e.errno == 98:  # Address already in use
            print(f"Error: Port {port} is already in use. Please choose a different port.")
        else:
            print(f"Error: {e}")
        sys.exit(1)  # Exit with error

if __name__ == "__main__":
    main()  # Run the main function

