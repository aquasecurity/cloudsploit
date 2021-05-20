var expect = require('chai').expect;
var dataDisksEncrypted = require('./dataDisksEncrypted.js');

const describeDisks = [
    {
        "DetachedTime": "",
        "Category": "cloud_essd",
        "Description": "",
        "KMSKeyId": "",
        "ResourceGroupId": "rg-aekzsj44b4lt5fa",
        "DedicatedBlockStorageClusterId": "",
        "Size": 40,
        "Encrypted": true,
        "DeleteAutoSnapshot": false,
        "DiskChargeType": "PostPaid",
        "ExpiredTime": "2999-09-08T16:00Z",
        "ImageId": "",
        "StorageSetId": "",
        "Tags": {
          "Tag": []
        },
        "Status": "Available",
        "AttachedTime": "",
        "ZoneId": "us-west-1b",
        "SourceSnapshotId": "",
        "ProductCode": "",
        "InstanceId": "",
        "PerformanceLevel": "PL1",
        "Device": "",
        "DeleteWithInstance": false,
        "EnableAutomatedSnapshotPolicy": false,
        "EnableAutoSnapshot": true,
        "AutoSnapshotPolicyId": "",
        "DiskName": "",
        "OperationLocks": {
            "OperationLock": []
        },
        "BdfId": "",
        "Portable": true,
        "Type": "data",
        "SerialNumber": "rj956ec1t8qrh97kei6k",
        "MountInstances": {
            "MountInstance": []
        },
        "CreationTime": "2021-05-06T10:23:18Z",
        "RegionId": "us-west-1",
        "DiskId": "d-rj956ec1t8qrh97kei6k"
    },
    {
        "DetachedTime": "",
        "Category": "cloud_essd",
        "KMSKeyId": "ed204e08-f814-4788-8406-3dc19c8e5260",
        "Description": "",
        "ResourceGroupId": "rg-aekzsj44b4lt5fa",
        "DedicatedBlockStorageClusterId": "",
        "Size": 20,
        "Encrypted": true,
        "DeleteAutoSnapshot": false,
        "DiskChargeType": "PostPaid",
        "ExpiredTime": "2999-09-08T16:00Z",
        "ImageId": "",
        "StorageSetId": "",
        "Tags": {
            "Tag": []
        },
        "Status": "Available",
        "AttachedTime": "",
        "ZoneId": "us-west-1b",
        "SourceSnapshotId": "",
        "ProductCode": "",
        "InstanceId": "",
        "PerformanceLevel": "PL1",
        "Device": "",
        "DeleteWithInstance": false,
        "EnableAutomatedSnapshotPolicy": false,
        "EnableAutoSnapshot": true,
        "AutoSnapshotPolicyId": "",
        "DiskName": "akhtar-made",
        "OperationLocks": {
            "OperationLock": []
        },
        "BdfId": "",
        "Portable": true,
        "Type": "data",
        "SerialNumber": "rj94pupgygkqr4y3rr59",
        "MountInstances": {
            "MountInstance": []
        },
        "CreationTime": "2021-05-05T18:31:03Z",
        "RegionId": "us-west-1",
        "DiskId": "d-rj94pupgygkqr4y3rr59"
    },
    {
        "DetachedTime": "",
        "Category": "cloud_efficiency",
        "Description": "",
        "KMSKeyId": "",
        "ResourceGroupId": "rg-aekzsj44b4lt5fa",
        "DedicatedBlockStorageClusterId": "",
        "Size": 20,
        "Encrypted": true,
        "DeleteAutoSnapshot": true,
        "DiskChargeType": "PostPaid",
        "ExpiredTime": "2999-09-08T16:00Z",
        "ImageId": "",
        "StorageSetId": "",
        "Tags": {
            "Tag": []
        },
        "Status": "In_use",
        "AttachedTime": "2021-05-05T11:56:22Z",
        "ZoneId": "us-west-1b",
        "InstanceId": "i-rj9cexclrthxbysg4w5x",
        "SourceSnapshotId": "",
        "ProductCode": "",
        "Device": "/dev/xvdb",
        "PerformanceLevel": "",
        "DeleteWithInstance": false,
        "EnableAutomatedSnapshotPolicy": false,
        "EnableAutoSnapshot": true,
        "AutoSnapshotPolicyId": "",
        "DiskName": "akhtar-made",
        "OperationLocks": {
            "OperationLock": []
        },
        "BdfId": "",
        "Portable": true,
        "Type": "data",
        "SerialNumber": "rj9jcm5n3s695mng74et",
        "MountInstances": {
            "MountInstance": []
        },
        "CreationTime": "2021-05-03T11:11:53Z",
        "RegionId": "us-west-1",
        "DiskId": "d-rj9jcm5n3s695mng74et"
    },
    {
        "DetachedTime": "2021-05-06T10:20:59Z",
        "Category": "cloud_efficiency",
        "Description": "",
        "KMSKeyId": "",
        "ResourceGroupId": "rg-aekzsj44b4lt5fa",
        "DedicatedBlockStorageClusterId": "",
        "Size": 20,
        "Encrypted": false,
        "DeleteAutoSnapshot": false,
        "DiskChargeType": "PostPaid",
        "ExpiredTime": "",
        "ImageId": "aliyun_2_1903_x64_20G_alibase_20210325.vhd",
        "StorageSetId": "",
        "Tags": {
            "Tag": [
                {
                    "TagKey": "acs:ecs:sourceInstanceId",
                    "TagValue": "i-rj9cexclrthxbysg4w5x"
                },
            {
                "TagKey": "acs:ecs:diskDeleteProtection",
                "TagValue": "true"
            },
            {
                "TagKey": "acs:ecs:diskPayType",
                "TagValue": "AfterPay"
            }
          ]
        },
        "Status": "Available",
        "AttachedTime": "2021-04-30T09:57:27Z",
        "ZoneId": "us-west-1b",
        "SourceSnapshotId": "",
        "ProductCode": "",
        "InstanceId": "",
        "Device": "",
        "PerformanceLevel": "",
        "DeleteWithInstance": true,
        "EnableAutomatedSnapshotPolicy": false,
        "EnableAutoSnapshot": true,
        "AutoSnapshotPolicyId": "",
        "DiskName": "",
        "OperationLocks": {
            "OperationLock": [
                {
                    "LockReason": "detached-system-disk"
                }
            ]
        },
        "BdfId": "",
        "Portable": true,
        "Type": "data",
        "SerialNumber": "rj947ftycv8s1xxvghaa",
        "MountInstances": {
            "MountInstance": []
        },
        "CreationTime": "2021-04-30T09:57:14Z",
        "RegionId": "us-west-1",
        "DiskId": "d-rj947ftycv8s1xxvghaa"
    }
];

const listKeys = [
    {
        "KeyId": "ed204e08-f814-4788-8406-3dc19c8e5260",
        "KeyArn": "acs:kms:us-west-1:0000111122223333:key/ed204e08-f814-4788-8406-3dc19c8e5260"
    }
];

const describeKey = [
    {
        "data": {
            "CreationDate": "2021-05-03T11:11:47Z",
            "Description": "",
            "KeyId": "ed204e08-f814-4788-8406-3dc19c8e5260",
            "KeySpec": "Aliyun_AES_256",
            "KeyState": "Enabled",
            "KeyUsage": "ENCRYPT/DECRYPT",
            "PrimaryKeyVersion": "9e42450c-fe3a-4bc0-93b5-e8074aa4b4c9",
            "DeleteDate": "",
            "Creator": "Ecs",
            "Arn": "acs:kms:us-west-1:0000111122223333:key/ed204e08-f814-4788-8406-3dc19c8e5260",
            "Origin": "Aliyun_KMS",
            "MaterialExpireTime": "",
            "ProtectionLevel": "SOFTWARE",
            "LastRotationDate": "2021-05-03T11:11:47Z",
            "AutomaticRotation": "Disabled"
        }
    }
];

const createCache = (disksData, listKeys, describeKeyData, disksErr, listKeysErr, describeKeyErr) => {
    let keyId = (listKeys && listKeys.length) ? listKeys[0].KeyId : null;
    return {
        ecs: {
            DescribeDisks: {
                'cn-hangzhou': {
                    data: disksData,
                    err: disksErr
                },
            }
        },
        kms: {
            ListKeys: {
                'cn-hangzhou': {
                    data: listKeys,
                    err: listKeysErr
                }
            },
            DescribeKey: {
                'cn-hangzhou': {
                    [keyId]: {
                        data: describeKeyData,
                        err: describeKeyErr
                    }
                }
            }
        }
    };
};

describe('dataDisksEncrypted', function () {
    describe('run', function () {
        it('should FAIL if disk is not encrypted', function (done) {
            const cache = createCache([describeDisks[3]], listKeys);
            dataDisksEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Data disk is not encrypted');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should FAIL if Data disk is not encrypted to target encryption level', function (done) {
            const cache = createCache([describeDisks[0]], listKeys);
            dataDisksEncrypted.run(cache, { data_disks_encryption_level: 'alibabacmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Data disk is not encrypted');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if data disks are encrypted', function (done) {
            const cache = createCache([describeDisks[0], describeDisks[2]], listKeys);
            dataDisksEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Data disk is encrypted');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should FAIL if Data disk is not encrypted to target level and combine results when reach results limit', function (done) {
            const cache = createCache([describeDisks[0], describeDisks[2]], listKeys);
            dataDisksEncrypted.run(cache, { data_disks_encryption_level: 'alibabacmk', data_disks_result_limit: '1' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('data disks are not encrypted');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no ECS disks found', function (done) {
            const cache = createCache([]);
            dataDisksEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ECS disks found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query ECS disks', function (done) {
            const cache = createCache([], null, null, { err: 'Unable to query ECS disks' });
            dataDisksEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query ECS disks');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})