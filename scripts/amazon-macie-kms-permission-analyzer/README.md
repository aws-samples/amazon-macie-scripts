# Amazon Macie Scripts - KMS Permission Analyzer

## Introduction
This project contains a Python3 script to help you identify the S3 buckets in an account Macie
cannot read from because of incompatible permissions configurations in the associated KMS key policies. This 
script will also generate a list of commands to correct incompatible configurations identified, which 
you can review and apply to enable Macie scans. 

For Macie to scan encrypted buckets, you need the following [Allow statement] to the associated KMS key policy.

[Allow statement]: https://docs.aws.amazon.com/macie/latest/user/discovery-supported-encryption-types.html#discovery-supported-encryption-cmk-configuration

``` json
{
 "Sid": "Allow the Macie service-linked role to use the key",
 "Principal": {
  "AWS": "...service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"
  },
 "Action": ["kms:Decrypt"],
 "Effect": "Allow",
 "Resource": "*"
}
```

This script uses [KMS Grants] to avoid dealing with complex policy updates. It 
identifies the specific keys in your account that Macie needs access to and suggests a list of commands for you to execute.

[KMS Grants]: https://docs.aws.amazon.com/kms/latest/developerguide/grants.html

Specifically, the script invokes the following APIs:

- `macie:GetMacieSession`
- `macie:DescribeBuckets`
- `s3:GetBucketEncryption`
- `kms:DescribeKey`
- `kms:GetKeyPolicy`
- `kms:ListGrants`

Note that all of these are read-only APIs. That is intentional, as this script does not make any
changes to your account. Instead, it compiles a simple `kms-todo.sh` script with a sequence of
ready-to-execute AWS CLI commands. You can open the script in an editor of your choice, review the
CLI commands, and if they look OK, apply them.

## Installation
Set up a Python3 virtual environment and install the required libraries.

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
The script makes API calls to Macie, S3, and KMS. You need to [configure credentials]
as you do for use with AWS CLI. The IAM principal configured must have the necessary permissions to invoke these
APIs.

[configure credentials]: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html

### Help
Once your Python environment is setup, you can run the help command like so:

```
python macie-kms-todo.py --help
```

### Running the script
The script takes one argument, `--region` to specify the AWS region you want to work with. This
is optional, and if you don't provide one, `us-east-1` is assumed.

```
python macie-kms-todo.py
```

or 

```
python macie-kms-todo.py --region us-west-2
```

After execution, the script produces two outputs:

#### Output to terminal: Summary

A tree of key identifiers along with the buckets that use the key. The key-ids have a ✔ against them
if Macie can decrypt data encrypted with the key; if not, a ✖ is shown. Here's a sample:

```
arn:aws:iam::111122223333:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie
    ├── ✔ a1b2c3d4-5678-90ab-cdef-EXAMPLE11111
    │   └── DOC-EXAMPLE-BUCKET1
    ├── ✔ a1b2c3d4-5678-90ab-cdef-EXAMPLE22222
    │   └── DOC-EXAMPLE-BUCKET2
    ├── ✔ a1b2c3d4-5678-90ab-cdef-EXAMPLE33333
    │   ├── DOC-EXAMPLE-BUCKET3
    │   └── DOC-EXAMPLE-BUCKET33
    ├── ✔ a1b2c3d4-5678-90ab-cdef-EXAMPLE44444
    │   ├── DOC-EXAMPLE-BUCKET4
    │   └── DOC-EXAMPLE-BUCKET44
    ├── ✔ a1b2c3d4-5678-90ab-cdef-EXAMPLE55555
    │   └── DOC-EXAMPLE-BUCKET5
    ├── ✖ a1b2c3d4-5678-90ab-cdef-EXAMPLE12345
    │   └── DOC-EXAMPLE-BUCKET6
    ├── ✔ a1b2c3d4-5678-90ab-cdef-EXAMPLE77777
    │   └── DOC-EXAMPLE-BUCKET7
    ├── ✔ a1b2c3d4-5678-90ab-cdef-EXAMPLE88888
    │   ├── DOC-EXAMPLE-BUCKET8
    │   └── DOC-EXAMPLE-BUCKET9
    ├── ✖ a1b2c3d4-5678-90ab-cdef-EXAMPLE99999
    │   └── DOC-EXAMPLE-BUCKET10
    ├── ✖ a1b2c3d4-5678-90ab-cdef-EXAMPLE00000
    │   └── DOC-EXAMPLE-BUCKET11
    ├── ✖ a1b2c3d4-5678-90ab-cdef-EXAMPLEaaaaa
    │   └── DOC-EXAMPLE-BUCKET12
    ├── ✖ a1b2c3d4-5678-90ab-cdef-EXAMPLEbbbbb
    │   └── DOC-EXAMPLE-BUCKET13
    └── ✖ a1b2c3d4-5678-90ab-cdef-EXAMPLEccccc
        └── DOC-EXAMPLE-BUCKET14
```

Please go over all the ✖s and turn them to ✔s if you'd like to enable Macie to scan the associated buckets.
To do that, the script produces a script `kms-todo.sh` that contains lines like:

```
# for bucket:
## DOC-EXAMPLE-BUCKET6
aws kms create-grant --key-id a1b2c3d4-5678-90ab-cdef-EXAMPLE12345 \
 --grantee-principal arn:aws:iam::111122223333:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie \
 --operations Decrypt
```

#### Output to file: kms-todo.sh

The comments identify the specific bucket the underlying grant opens up. Each command targets 1 KMS
key (identified by its key-id). You should review these carefully. If they look good, you can enable
all these by executing the script:

```
sh kms-todo.sh
```

When run, this creates KMS grants for the Macie service role to invoke the `Decrypt` operation
specifically. This is a reversible operation. See [RevokeGrant] for details.

[RevokeGrant]: https://docs.aws.amazon.com/kms/latest/APIReference/API_RevokeGrant.html

## Troubleshooting

- S3 Bucket with cross-account access to a customer managed key.
  - This script does not support this scenario.
  - If one account owns the AWS KMS key (key owner) and a different account owns the bucket (bucket owner), the key owner has to provide the bucket owner with cross-account access to the KMS key. Please follow this documentation on the recommended setup:https://docs.aws.amazon.com/macie/latest/user/discovery-supported-encryption-types.html#discovery-supported-encryption-cmk-configuration.

- AccessDeniedException
  - This script requires access to these APIs. Please review and make sure the corresponding resources and the IAM principal configured have the necessary permissions to invoke these
APIs.
    - Macie
      - `macie:GetMacieSession`
      - `macie:DescribeBuckets`
    - S3
      - `s3:GetBucketEncryption`
    - KMS 
      - `kms:DescribeKey`
      - `kms:GetKeyPolicy`
      - `kms:ListGrants`
      