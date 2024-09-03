import os
import logging
import jsonpickle
import argparse
from flask import Flask, request


app = Flask(__name__)

log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)
app.logger.disabled = True
log.disabled = True

parser = argparse.ArgumentParser(description="TODO")
parser.add_argument("--policy-dir", help="path to a directory containing policies to be evaluated")
args = parser.parse_args()

# curl -X 'POST' \
#   'http://127.0.0.1:5000' \
#   -H 'accept: application/json' \
#   -H 'Content-Type: application/json' \
#   -d '{
#     "user": "hiro"
#     }'


@app.route("/test-api", methods=["GET", "POST"])
def index():

    headers = {}
    for key, val in request.headers.items():
        headers[key] = val
    query_params = None
    if request.args:
        query_params = {}
        for key, val in request.args.items():
            query_params[key] = val
    post_data = request.json if request.mimetype == "application/json" else None
    rest_request = dict(
        headers=headers,
        path=request.path,
        method=request.method,
        query_params=query_params,
        post_data=post_data,
    )

    return jsonpickle.encode(rest_request, make_refs=False)


if __name__ == "__main__":
    app.run(debug=True)
