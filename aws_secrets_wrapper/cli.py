#!/usr/bin/env python3
from argparse import ArgumentParser
from base64 import b64decode, b64encode
from json import dumps, loads, JSONDecodeError
from logging import getLogger
from re import compile
from sys import stdin
from typing import Tuple, TYPE_CHECKING


from aws_secrets_env.secretsmanager import handle_secret
from boto3 import client
from botocore.exceptions import ClientError
from fernet import Fernet

from .wrap import Wrapper

if TYPE_CHECKING:
    from mypy_boto3_kms.client import KMSClient
    from mypy_boto3_lambda import LambdaClient
    from mypy_boto3_secretsmanager import SecretsManagerClient
else:
    KMSClient = object
    LambdaClient = object
    SecretsManagerClient = object


getLogger().setLevel("INFO")
getLogger("botocore").setLevel("CRITICAL")
getLogger("boto3").setLevel("CRITICAL")


LAMBDA: LambdaClient = client("lambda")
KMS_CLIENT: KMSClient = client("kms")
SECRETS_MANAGER: SecretsManagerClient = client("secretsmanager")
ANSI_RE = compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
WRAP_FUNCTION = "secrets-wrap"


def get_secret(
    secret: str, client: SecretsManagerClient = SECRETS_MANAGER
) -> str | dict:
    res = client.get_secret_value(SecretId=secret)
    val = handle_secret(res)
    return val


def invoke(
    payload: str | dict,
    lambda_client: LambdaClient = LAMBDA,
    func_name: str = WRAP_FUNCTION,
) -> dict:
    res = (
        lambda_client.invoke(
            FunctionName=func_name,
            InvocationType="RequestResponse",
            Payload=dumps(payload),
        )["Payload"]
        .read()
        .decode()
    )

    res = loads(res)

    if "error" in res:
        print(dumps(res, indent=2))
        exit(1)

    return res


def decrypt_datakey(
    key_name: str, datakey: bytes, kms_client: KMSClient = KMS_CLIENT
) -> str:
    try:
        return Wrapper.decrypt_data_key(
            key_name, b64decode(datakey), kms_client=kms_client
        )
    except (
        kms_client.exceptions.NotFoundException,
        kms_client.exceptions.DisabledException,
        kms_client.exceptions.KeyUnavailableException,
    ) as e:
        print(e)
        exit(1)
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            print(e)
            exit(1)
        else:
            raise e


def get_keys(kms_key: str, kms_client: KMSClient) -> Tuple[Fernet, bytes]:
    try:
        key_obj, data_key = Wrapper.get_keys(kms_key, kms_client=kms_client)
        return key_obj, data_key
    except (
        kms_client.exceptions.NotFoundException,
        kms_client.exceptions.DisabledException,
        kms_client.exceptions.KeyUnavailableException,
    ) as e:
        getLogger.error(e)
        exit(1)
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            getLogger().error(e)
            exit(1)
        else:
            raise e


def unwrap(
    kms_client: KMSClient = KMS_CLIENT,
    lambda_client: LambdaClient = LAMBDA,
    wrap_function: str = WRAP_FUNCTION,
) -> None:
    parser = ArgumentParser()
    parser.add_argument(
        "token", type=str, help="The unwrap token to use for retrieving your secret."
    )
    args = parser.parse_args()

    # Strip leading and trailing quotes from token
    opts = {"token": args.token.replace('"', "").replace("'", "")}
    res = invoke(opts, lambda_client, wrap_function)

    decoded_val = b64decode(res["value"])
    key_obj = decrypt_datakey(res["kms_key"], res["data_key"], kms_client)
    value = key_obj.decrypt(decoded_val).decode()

    try:
        value = loads(value)
    except JSONDecodeError:
        pass

    res = {"value": value, "created_at": res["created_at"]}
    print(dumps(res, indent=2, default=lambda x: str(x)))


def wrap(
    kms_client: KMSClient = KMS_CLIENT,
    lambda_client: LambdaClient = LAMBDA,
    secrets_client: SecretsManagerClient = SECRETS_MANAGER,
    wrap_function: str = WRAP_FUNCTION,
) -> None:
    parser = ArgumentParser()
    parser.add_argument(
        "-k",
        "--kms-key",
        type=str,
        help="The ID, Arn, or alias of a KMS key to use for client-side encryption. You must have `kms:Encrypt` and `kms:GenerateDataKey` permissions to wrap and `kms:Decrypt` and `kms:GenerateDataKey` permissions to unwrap",
        default="alias/wrap-client",
    )
    parser.add_argument(
        "-t",
        "--ttl",
        type=int,
        help="The number of seconds before the wrap token expires and the secret is deleted",
        default=900,
    )

    parser.add_argument(
        "-s",
        "--from-secret",
        help="Use value as the name of a secret to wrap the value of",
        action="store_true",
    )

    if not stdin.isatty():
        val = ANSI_RE.sub("", stdin.read().rstrip())
        parser.add_argument("--value", type=str, default=val)
    else:
        parser.add_argument("value", type=str, help="The value to wrap.")

    args = parser.parse_args()

    if args.from_secret:
        val = get_secret(args.value, secrets_client)
    else:
        val = args.value

    if not val:
        parser.print_usage()
        print("Missing secret value")
        exit(1)

    if not isinstance(val, str):
        val = dumps(val, default=lambda x: str(x))

    key_obj, data_key = get_keys(args.kms_key, kms_client=kms_client)

    opts = {
        "value": b64encode(key_obj.encrypt(val.encode())).decode(),
        "client_kms_key": args.kms_key,
        "data_key": b64encode(data_key).decode(),
        "ttl": Wrapper.make_expiration(args.ttl),
    }

    res = invoke(opts, lambda_client, wrap_function)
    print(res)
