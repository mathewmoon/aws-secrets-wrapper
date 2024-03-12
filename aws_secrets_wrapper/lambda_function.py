#!/usr/bin/env python3
from logging import getLogger
from os import environ

from botocore.exceptions import ClientError

from .wrap import NotFoundError, Wrapper


getLogger().setLevel("INFO")


def handler(event, _) -> dict:
    try:
        Wrapper.prune_expired_records()
    except (Exception, ClientError) as e:
        getLogger().exception(e)

    if event.get("prune_only"):
        return

    try:
        if event.get("token"):
            res = Wrapper.unwrap(token=event["token"])
            return res

        else:
            event["lambda_kms_key"] = environ["KMS_KEY"]

            secret = Wrapper(**event)
            token = secret.wrap()
            return token
    except (
        Wrapper.kms_client.exceptions.NotFoundException,
        Wrapper.kms_client.exceptions.DisabledException,
        Wrapper.kms_client.exceptions.KeyUnavailableException,
    ) as e:
        getLogger().exception(e)
        return {"error": "KMSError", "error_message": str(e)}
    except NotFoundError as e:
        return {"error": e.__class__.__name__, "error_message": str(e)}
    except (Exception, ClientError) as e:
        getLogger().exception(e)
        return {"error": None, "error_message": "An unknown error has occurred."}
