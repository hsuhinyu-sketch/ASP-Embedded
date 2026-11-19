#!/usr/bin/env python3
"""Read-only loopback MCP server for the local device assistant. No shell or file operations."""
import argparse
import http.server
import json
import os
import platform


TOOL = {
    'name': 'device_info',
    'description': 'Read operating system, kernel, CPU architecture and logical CPU count.',
    'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False},
    'annotations': {'readOnlyHint': True, 'destructiveHint': False},
}


def handle(request):
    method = request.get('method')
    if method == 'initialize':
        return {'protocolVersion': '2025-11-25', 'capabilities': {'tools': {}},
                'serverInfo': {'name': 'edge-device', 'version': '1.0'}}
    if method == 'ping':
        return {}
    if method == 'tools/list':
        return {'tools': [TOOL]}
    if method == 'tools/call':
        params = request.get('params', {})
        if params.get('name') != TOOL['name'] or params.get('arguments', {}) != {}:
            raise ValueError('only device_info with empty arguments is supported')
        info = {'system': platform.system(), 'kernel': platform.release(),
                'architecture': platform.machine(), 'logicalCpus': os.cpu_count()}
        return {'content': [{'type': 'text', 'text': json.dumps(info)}], 'isError': False}
    raise ValueError('unsupported method')


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        if self.path != '/mcp':
            self.send_error(404)
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 65536:
                raise ValueError('invalid message length')
            request = json.loads(self.rfile.read(length))
            if not isinstance(request, dict):
                raise ValueError('expected JSON-RPC object')
        except ValueError:
            self.send_error(400)
            return
        if 'id' not in request:
            self.send_response(202)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        try:
            response = {'result': handle(request)}
        except ValueError as error:
            response = {'error': {'code': -32602, 'message': str(error)}}
        body = json.dumps({'jsonrpc': '2.0', 'id': request['id'], **response}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=18082)
    args = parser.parse_args()
    http.server.ThreadingHTTPServer(('127.0.0.1', args.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
