# Wrap and unwrap AWS secrets, similar to Vault

## Usage
```shell
~  > awswrap -h
usage: awswrap [-h] [-k KMS_KEY] [-t TTL] [-s] value

positional arguments:
  value                 The value to wrap.

options:
  -h, --help            show this help message and exit
  -k KMS_KEY, --kms-key KMS_KEY
                        The ID, Arn, or alias of a KMS key to use for client-side encryption. You must have `kms:Encrypt` and `kms:GenerateDataKey` permissions to wrap and `kms:Decrypt` and `kms:GenerateDataKey` permissions to unwrap
  -t TTL, --ttl TTL     The number of seconds before the wrap token expires and the secret is deleted
  -s, --from-secret     Use value as the name of a secret to wrap the value of
```

## How it works
### Wrapping:
* Client generates a key pair, using KMS, and encrypts a secret value
* Client sends both the secret an encrypted version of the key that encrypted the secret to Lambda
* Lambda generates a truly random token to use as a database key for the secret
* Lambda generates a key pair from its own KMS key to add another layer of encryption to the secret value then stores the secret value, the client's encrypted key, and it's own encrypted key in the db (Where it's also encrypted at rest)
* Lambda returns back the token

The user shares that token with another user so they can retrieve the secret.

### Unwrapping
* Client calls Lambda with the wrap token
* If there is a secret stored with that token attached then Lambda retrieves it with a guarantee that the secret gets deleted from Dynamo
* Lambda uses its KMS key to decrypt the envelope encryption key that it used before to decrypt the data. The data is still encrypted with the client's key
* Lambda returns the data, the client's encrypted private key that was stored with the data, and the creation date to the client
* Client calls KMS to decrypt the temporary key that it had stored with the secret value
* Client decrypts the secret with the temporary key
* Client returns the now unencrypted secret

## Security and permissions
### KMS:
* It's highly recommended to use CMK's for all KMS keys involved. This allows fine tuning permissions on the key policies.

### Clients:
* Each request requires that the wrapping client have permission to call `kms:Encrypt` and `kms:GenerateDataKey` on the key used in the request (defaults to alias/aws/secretsmanager)
* The KMS key used for wrapping a secret can be specified as a commandline argument. During the unwrapping process they key alias is retreived from the record.
* The unwrapping client must have `kms:Decrypt` permission on the same key that the secret they are unwrapping was encrypted with by the original client.
* Specifying `-s` requires that the wrapping client have both permission to the secret to be wrapped and the underlying KMS key used to encrypt that secret in SecretsManager
* Using a CMK with an alias is preferred. This allows adding an explicit deny for Lambda on the key policy for even more protection.

### Lambda:
* Lambda should use its own KMS key for envelope encryption
* Lambda's KMS key should have an explicit deny on `kms:Decrypt` and `kms:GenerateDataKey` operations for any identitities other than itself.
* Lambda should be explicitly denied `kms:Decrypt` and `kms:GenerateDataKey` or the ability to modify the policy on the key used by clients for best security.

### Dynamodb:
* All data in the Dynamodb table has been envelope ecrypted twice, once by the client and once by Lambda, before being inserted.
* For the most enhanced security you can limit who has read access to the table using SCP's
* The Dynamodb table should use it's own CMK and have an explicit deny that only allows the wrap Lambda function and administrators to decrypt using the key or modify its policy.

### Why all the keys????
If all keys are managed as noted above, then the following applies:
1. At no point of the process can any entity involved decrypt the data without access to at least one KMS key AND the temporary key that was used to encrypt the data. Even having the key that encrypted the data is useless because the data key itself has to be decrypted by KMS
2. Even if you were to gain access to Lambda from inside of AWS you can't decode the data that the client passes because you don't have access to they key that decrypts their data key from inside of the Lambda
3. Even if you have access to the data key that encrypted the data by the client AND the KMS key that encrypted that key you still can't do anything with the data in Dynamodb because Lambda has also added it's encryption to both the data and the keys.
4. Even if you were to somehow gain access to Lambda's key and the client's key you would still need access to the Dynamodb table's key to access data directly from the table inside of AWS


## Examples
Wrap and then unwrap a simple string

```shell
~  > awswrap foo
zy-_zBb2MruhTlfxTzkbqlgskVAmg8CM_FCusq0n2-9pyZUDIo9Mg6Lwg0MgnxYdu_JUN2QUNyY-bJ2Qki6S76UViFsQ6pHoMxDO6gAPVltxF7qrytrr1mjC1NPYVg353aJh2mYkuB0n_wbZ0yh7c6YNAwp8PmALdt5W6QiGMzE
~  > awsunwrap zy-_zBb2MruhTlfxTzkbqlgskVAmg8CM_FCusq0n2-9pyZUDIo9Mg6Lwg0MgnxYdu_JUN2QUNyY-bJ2Qki6S76UViFsQ6pHoMxDO6gAPVltxF7qrytrr1mjC1NPYVg353aJh2mYkuB0n_wbZ0yh7c6YNAwp8PmALdt5W6QiGMzE
{
  "value": "foo",
  "created_at": "2024-03-12T14:36:41.150264"
}
```

Specify an existing secret to wrap
```shell
~  > awswrap -s mmoon-test/2
hamPeASmOStDYcpG2hI7juLeizjEA23CQGg08xB3wE9gj_X9aBytAYyBW2_jbMWE-jl0PzW7ZeNQCAkdatBGHbLo57x3zrNW3D0Ag3VnYTOfQP8Ctv2kbzH52V0ZRI86bTOPMYvMNb8UTdKbUXq40mHoUes_1E4614nIuaINlog
~  > awsunwrap Uhg8BjDTMtDpWdoTzsRCpuY8VZbjrYcUHUhBXQiDQDSI9-ydgQ8xQPHbI2uRQe12hajB9rYnBgBwZ5vnxjREggktYyksIWItp2WcQxRSicbvZZgTJFiFKHT_H23-OaEJplwG8dkOKXuCukIwB9mjX-wqsiGmdMYUOlTIwEGxvfA
{
  "value": {
    "test": "val1"
  },
  "created_at": "2024-03-12T14:39:12.273922"
}
```

## Building the Lambda
To build the Lambda function, clone the repo and run build-lambda.sh. This will create a zip file with the code to upload to AWS.