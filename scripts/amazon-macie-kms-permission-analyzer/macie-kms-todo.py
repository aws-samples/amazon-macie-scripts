#!/usr/bin/env python3
import typer
import boto3
from botocore.config import Config
import json
import botocore.exceptions
from typing import Optional, List, Set

from rich.tree import Tree
from rich import print

app = typer.Typer(pretty_exceptions_show_locals=False)

def macie_service_role(macie) -> str:
    """
    Check if Macie is enabled and retrieve the service role name.
    """
    session = macie.get_macie_session()
    if session['status'] != 'ENABLED':
        raise "Macie is not enabled"
    return session['serviceRole']


def get_encrypted_buckets(macie, region: str, account: str) -> list[str]:
    """
    Identify and retrieve encrypted buckets in the specified region. This uses Macie
    DescribeBucket API, which allows filtering for buckets that have encryption turned on.
    """
    buckets = []
    paginator = macie.get_paginator('describe_buckets')
    pages = paginator.paginate(criteria={'accountId': {'eq': [account]}})
    for page in pages:
        buckets.extend(page["buckets"])
    return [bucket['bucketName'] for bucket in buckets
            if bucket['region'] == region
            and 'serverSideEncryption' in bucket
            and 'type' in bucket['serverSideEncryption'] 
            and bucket['serverSideEncryption']['type'] == 'aws:kms'
            and 'kmsMasterKeyId' in bucket['serverSideEncryption']
            and len(bucket['serverSideEncryption']['kmsMasterKeyId']) > 0]


def bucket_encryption(s3, bucket: str) -> Optional[List[str]]:
    """
    Check if the bucket is encrypted and if it is, return the KMS key ARN.
    """
    key_id = 'KMSMasterKeyID'
    sse = 'ApplyServerSideEncryptionByDefault'
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket)
        if 'ServerSideEncryptionConfiguration' in enc:
            rules = enc['ServerSideEncryptionConfiguration']['Rules']
            return [r[sse][key_id] for r in rules if sse in r and key_id in r[sse]]
    except botocore.exceptions.ClientError as e:
        print(e)
        print(f":warn: Inconsistency: according to Macie {bucket} should have encryption settings. It doesn't.")
        return None


def macie_can_access(kms, kmd, kid: str, role: str) -> bool:
    """
    Check if the Key policy configuration is supported by Macie.
    """
    # Macie has access to the default keys
    if kmd['KeyManager'] == 'AWS':
        return True

    # This should never happen, because we're only looking at keys associated with buckets
    if kmd['KeySpec'] != 'SYMMETRIC_DEFAULT':
        return False

    # Only CMK is supported.
    if kmd['KeyManager'] != 'CUSTOMER':
        return False

    # Otherwise, this is a key that Macie can have access to, check the policy
    policy = json.loads(kms.get_key_policy(KeyId=kid, PolicyName='default')['Policy'])

    # Look through all policy statements, if any of them ALLOWs access to Macie Service Role
    for statement in policy['Statement']:
        if statement['Effect'] == 'Allow':
            principal = statement['Principal']
            if 'AWS' in principal and role in str(principal['AWS']):
                return True

    # List grants given to the service linked role
    grants = kms.list_grants(KeyId=kid, GranteePrincipal=role)["Grants"]
    for grant in grants:
        if "Operations" in grant and "Decrypt" in grant["Operations"]:
            return True

    # If we get to this line, then assume Macie does not have access.
    return False


def pretty_print(key_to_buckets: dict[str, Set[str]], key_to_access: dict[str, bool], account: str, region: str):
    """
    Pretty-print formatting. 
    Check mark indicates no issue identified.
    Crossed mark indicates an access issue is found.
    """
    tree = Tree("Macie KMS Access").add(account)
    region = tree.add(region)

    for kid, buckets in key_to_buckets.items():
        if key_to_access[kid]:
            kid_tree = region.add(f"[green]:heavy_check_mark:[/green] {kid}")
        else:
            kid_tree = region.add(f"[red]:heavy_multiplication_x:[/red] {kid}")
        for bucket in buckets:
            kid_tree.add(bucket, style="dim", guide_style="dim")

    print(tree)
    pass


def generate_script(key_to_buckets: dict[str, Set[str]], key_to_access: dict[str, bool], role: str, region: str):
    """
    Generate a shell script with AWS CLI commands to grant Macie access.
    """
    lines = []
    # Generate a list of commands we want to run
    for kid, buckets in key_to_buckets.items():
        if not key_to_access[kid]:
            lines.append("# for bucket:\n")
            for b in buckets:
                lines.append(f"## {b} \n")
            lines.append(f"aws kms create-grant --region {region} "
                         f"--key-id {kid} --grantee-principal {role} "
                         f"--operations Decrypt \n")
            lines.append("\n\n")

    # Write it to the current directory
    script_file = "kms-todo.sh"
    with open(script_file, 'w') as script:
        script.writelines(lines)


@app.command()
def list_macie_access(region: str = typer.Option("us-east-1", help="AWS Region")):
    """
    List buckets that Macie cannot read because they are encrypted with KMS keys that Macie does not have access to.
    Pretty print the KMS keys for visual review and generate a shell script to make the necessary changes.
    """
    config = Config(region_name=region)
    s3 = boto3.client('s3', config=config)
    kms = boto3.client('kms', config=config)
    sts = boto3.client('sts', config=config)
    macie = boto3.client('macie2', config=config)

    # Get the current caller identity.
    account = sts.get_caller_identity()['Account']

    # Check if Macie is enabled and fetch the service role
    role = macie_service_role(macie)

    # Get the buckets in the region using Macie DescribeBuckets
    buckets = get_encrypted_buckets(macie, region, account)

    # A dictionary of key identifiers to buckets that use it.
    key_to_buckets = {}

    # A dictionary of key identifier to whether Macie can access it.
    key_to_access = {}

    # Analyze buckets and generate updates if necessary
    for bucket in buckets:
        encryption_setting = bucket_encryption(s3, bucket)

        # Bucket is not encrypted, nothing to do
        if encryption_setting is None:
            continue

        # Check if the key needs updates
        for kms_arn in encryption_setting:
            kmd = kms.describe_key(KeyId=kms_arn)['KeyMetadata']
            kid = kmd['KeyId']

            if kid not in key_to_buckets:
                key_to_buckets[kid] = set([])

            key_to_buckets[kid].add(bucket)
            key_to_access[kid] = macie_can_access(kms, kmd, kid, role)

    pretty_print(key_to_buckets, key_to_access, role, account)
    generate_script(key_to_buckets, key_to_access, role, region)


if __name__ == '__main__':
    app()
