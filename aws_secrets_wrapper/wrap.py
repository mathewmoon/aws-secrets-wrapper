#!/usr/bin/env python3
from base64 import b64encode
from datetime import datetime, timedelta
from logging import getLogger, StreamHandler
from os import environ
from re import compile
from secrets import token_urlsafe
from sys import stderr
from typing import Any, Tuple, TYPE_CHECKING


from boto3 import resource, client
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from fernet import Fernet


if TYPE_CHECKING:
    from mypy_boto3_kms.client import KMSClient
    from mypy_boto3_secretsmanager.client import SecretsManagerClient
    from mypy_boto3_lambda.client import LambdaClient
else:
    KMSClient = object
    LambdaClient = object
    SecretsManagerClient = object


getLogger().setLevel("INFO")
getLogger("botocore").setLevel("CRITICAL")
getLogger("boto3").setLevel("CRITICAL")


ANSI_RE = compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
WRAP_FUNCTION = "aws-secrets-wrap"
LAMBDA: LambdaClient = client("lambda")
KMS_CLIENT: KMSClient = client("kms")
SECRETS_MANAGER: SecretsManagerClient = client("secretsmanager")


if environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    TABLE = resource("dynamodb").Table(environ["TABLE"])
else:
    TABLE = None
    getLogger().addHandler(StreamHandler(stream=stderr))


class NotFoundError(Exception):
    pass


class Wrapper:
    table = TABLE
    secret_pk = "WRAPPED_SECRET"

    def __init__(
        self,
        value: bytes,
        data_key: bytes,
        client_kms_key: str,
        lambda_kms_key: str,
        ttl: int = 900,
        kms_client: KMSClient = KMS_CLIENT,
    ):
        #: The value to wrap
        self.value: Any = value
        #: The KMS key id, alias, or ARN used by the client to generate the data key used for encrypting the value
        self.client_kms_key: str = client_kms_key
        #: Timestamp, after which the secret will be deleted
        self.ttl: int = ttl
        #: The encrypted data key that was used to encrypt the secret
        self.data_key: bytes = data_key
        #: The KMS key id, alias, or ARN that Lambda should use for re-encrypting the value
        self.lambda_kms_key: str = lambda_kms_key
        #: The token that will be returned to the user and shared for unwrapping
        self.token: str = token_urlsafe(128)
        #: A `Fernet` object and encrypted data key based off of the Lambda's KMS key
        self.lambda_key_obj, self.lambda_data_key = self.get_keys(self.lambda_kms_key)
        #: The boto3 KMS client to use by default
        self.kms_client: KMSClient = kms_client

    @classmethod
    def prune_expired_records(cls):
        res = TABLE.query(
            KeyConditionExpression=Key("pk").eq(cls.secret_pk),
            FilterExpression=Attr("ttl").lte(int(datetime.now().timestamp())),
        )["Items"]
        for record in res:
            TABLE.delete_item(Key={"pk": record["pk"], "sk": record["sk"]})

    @classmethod
    def make_expiration(cls, ttl: int):
        expires = int((datetime.now() + timedelta(seconds=ttl)).timestamp())
        return expires

    @classmethod
    def decrypt_data_key(
        cls, kms_key: str, data_key: bytes, kms_client: KMSClient = KMS_CLIENT
    ) -> Fernet:
        """
        Takes a KMS key id, alias, or ARN and and a data key to decrypt. Returns a
        `Fernet` object that can be used for crypto operations by decrypting the data key.
        """
        res = kms_client.decrypt(KeyId=kms_key, CiphertextBlob=data_key)
        key = Fernet(b64encode(res["Plaintext"]))
        return key

    @classmethod
    def get_keys(
        cls, kms_key: str, kms_client: KMSClient = KMS_CLIENT
    ) -> Tuple[Fernet, bytes]:
        """
        Takes a KMS key ID, ARN or alias and returns a `Fernet` object that can be
        used for crypto operations as well as an encrypted data key as bytes.
        """
        try:
            res = kms_client.generate_data_key(KeyId=kms_key, KeySpec="AES_256")
        except ClientError as e:
            getLogger().error(e)
            exit()
        key_obj = Fernet(b64encode(res["Plaintext"]))
        encrypted_key = res["CiphertextBlob"]
        return key_obj, encrypted_key

    @property
    def _prepared_item(self) -> dict:
        # Encrypt the value using Lambda's data key and then return a dict for the db
        return dict(
            created_at=datetime.now().isoformat(),
            ttl=self.ttl,
            value=self.lambda_key_obj.encrypt(self.value),
            data_key=self.data_key,
            kms_key=self.client_kms_key,
            token=self.token,
            lambda_kms_key=self.lambda_kms_key,
            lambda_data_key=self.lambda_data_key,
        )

    def wrap(self) -> str:
        """
        Stores a secret in the table and returns the unwrap token
        """
        item = {"pk": self.secret_pk, "sk": self.token, **self._prepared_item}

        self.table.put_item(Item=item)
        return self.token

    @classmethod
    def unwrap(cls, token: str) -> dict:
        """
        Returns a wrapped item after decrypting the Lambda's layer of encryption on the value.
        """
        # Call delete on the item but return the value
        res = cls.table.delete_item(
            Key={"pk": cls.secret_pk, "sk": token}, ReturnValues="ALL_OLD"
        )
        try:
            res = res["Attributes"]
        except KeyError:
            raise NotFoundError("No secret found using the provided token.")

        # Decrypt the data key that Lambda used to re-encrypt the value
        key_obj = cls.decrypt_data_key(
            res["lambda_kms_key"], bytes(res["lambda_data_key"])
        )

        # Decrypt the value back to only the client's encryption
        value = key_obj.decrypt(bytes(res["value"]))

        res = {
            "value": value,
            "created_at": res["created_at"],
            "kms_key": res["kms_key"],
            "data_key": res["data_key"],
        }

        return res
