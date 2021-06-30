var expect = require("chai").expect;
var systemDisksEncrypted = require("./systemDisksEncrypted.js");

const describeDisks = [
  {
    "DetachedTime": "",
    "KMSKeyId": "ed204e08-f814-4788-8406-3dc19c8e5260",
    "Category": "cloud_essd",
    "Description": "",
    "ResourceGroupId": "rg-aekzqtoj2lxbgmq",
    "DedicatedBlockStorageClusterId": "",
    "Encrypted": true,
    "Size": 20,
    "DeleteAutoSnapshot": false,
    "DiskChargeType": "PostPaid",
    "MultiAttach": "Disabled",
    "ExpiredTime": "2999-09-08T16:00Z",
    "ImageId": "",
    "StorageSetId": "",
    "Tags": { Tag: [] },
    "Status": "Available",
    "AttachedTime": "",
    "ZoneId": "us-west-1b",
    "SourceSnapshotId": "",
    "InstanceId": "",
    "ProductCode": "",
    "PerformanceLevel": "PL1",
    "Device": "",
    "DeleteWithInstance": false,
    "EnableAutomatedSnapshotPolicy": false,
    "EnableAutoSnapshot": true,
    "AutoSnapshotPolicyId": "",
    "DiskName": "encrypted_disk",
    "OperationLocks": { OperationLock: [] },
    "BdfId": "",
    "Portable": true,
    "Type": "data",
    "SerialNumber": "rj9jd5ee7h54aax5xdp0",
    "CreationTime": "2021-06-15T13:21:49Z",
    "RegionId": "us-west-1",
    "DiskId": "d-rj9jd5ee7h54aax5xdp0",
  },
  {
    "DetachedTime": "",
    "Category": "cloud_essd",
    "Description": "",
    "KMSKeyId": "",
    "ResourceGroupId": "rg-acfnsrchcdcbvfa",
    "DedicatedBlockStorageClusterId": "",
    "Encrypted": true,
    "Size": 120,
    "DeleteAutoSnapshot": false,
    "DiskChargeType": "PostPaid",
    "MultiAttach": "Disabled",
    "Attachments": { },
    "ExpiredTime": "2999-09-08T16:00Z",
    "ImageId": "aliyun_2_1903_x64_20G_alibase_20210325.vhd",
    "StorageSetId": "",
    "Tags": { Tag: [Array] },
    "Status": "In_use",
    "AttachedTime": "2021-05-25T14:07:23Z",
    "ZoneId": "us-west-1a",
    "InstanceId": "i-rj9ai23qaqnabm6i23dd",
    "SourceSnapshotId": "",
    "ProductCode": "",
    "PerformanceLevel": "PL1",
    "Device": "/dev/xvda",
    "DeleteWithInstance": true,
    "EnableAutomatedSnapshotPolicy": false,
    "EnableAutoSnapshot": true,
    "AutoSnapshotPolicyId": "",
    "DiskName": "",
    "OperationLocks": { OperationLock: [] },
    "BdfId": "",
    "Portable": true,
    "Type": "system",
    "SerialNumber": "rj94hrde98wgfuvoc6ei",
    "CreationTime": "2021-05-25T14:07:19Z",
    "RegionId": "us-west-1",
    "DiskId": "d-rj94hrde98wgfuvoc6ei",
  },
  {
    "DetachedTime": "",
    "Category": "cloud_essd",
    "Description": "",
    "KMSKeyId": "ed204e08-f814-4788-8406-3dc19c8e5260",
    "ResourceGroupId": "rg-acfnsrchcdcbvfa",
    "DedicatedBlockStorageClusterId": "",
    "Encrypted": true,
    "Size": 120,
    "DeleteAutoSnapshot": false,
    "DiskChargeType": "PostPaid",
    "MultiAttach": "Disabled",
    "Attachments": { },
    "ExpiredTime": "2999-09-08T16:00Z",
    "ImageId": "aliyun_2_1903_x64_20G_alibase_20210325.vhd",
    "StorageSetId": "",
    "Tags": { Tag: [Array] },
    "Status": "In_use",
    "AttachedTime": "2021-05-25T14:07:23Z",
    "ZoneId": "us-west-1a",
    "InstanceId": "i-rj9ai23qaqnabm6i23df",
    "SourceSnapshotId": "",
    "ProductCode": "",
    "PerformanceLevel": "PL1",
    "Device": "/dev/xvda",
    "DeleteWithInstance": true,
    "EnableAutomatedSnapshotPolicy": false,
    "EnableAutoSnapshot": true,
    "AutoSnapshotPolicyId": "",
    "DiskName": "",
    "OperationLocks": { OperationLock: [] },
    "BdfId": "",
    "Portable": true,
    "Type": "system",
    "SerialNumber": "rj94hrde98wgfuvoc6ek",
    "CreationTime": "2021-05-25T14:07:19Z",
    "RegionId": "us-west-1",
    "DiskId": "d-rj94hrde98wgfuvoc6ek",
  },
  {
    "DetachedTime": "",
    "Category": "cloud_essd",
    "Description": "",
    "KMSKeyId": "",
    "ResourceGroupId": "rg-acfnsrchcdcbvfa",
    "DedicatedBlockStorageClusterId": "",
    "Encrypted": false,
    "Size": 120,
    "DeleteAutoSnapshot": false,
    "DiskChargeType": "PostPaid",
    "MultiAttach": "Disabled",
    "Attachments": { },
    "ExpiredTime": "2999-09-08T16:00Z",
    "ImageId": "aliyun_2_1903_x64_20G_alibase_20210325.vhd",
    "StorageSetId": "",
    "Tags": { Tag: [Array] },
    "Status": "In_use",
    "AttachedTime": "2021-05-25T14:07:23Z",
    "ZoneId": "us-west-1a",
    "InstanceId": "i-rj9ai23qaqnabm6i23de",
    "SourceSnapshotId": "",
    "ProductCode": "",
    "PerformanceLevel": "PL1",
    "Device": "/dev/xvda",
    "DeleteWithInstance": true,
    "EnableAutomatedSnapshotPolicy": false,
    "EnableAutoSnapshot": true,
    "AutoSnapshotPolicyId": "",
    "DiskName": "",
    "OperationLocks": { OperationLock: [] },
    "BdfId": "",
    "Portable": true,
    "Type": "system",
    "SerialNumber": "rj94hrde98wgfuvoc6ej",
    "CreationTime": "2021-05-25T14:07:19Z",
    "RegionId": "us-west-1",
    "DiskId": "d-rj94hrde98wgfuvoc6ej",
  },
];
const listKeys = [
  {
    "KeyId": "ed204e08-f814-4788-8406-3dc19c8e5260",
    "KeyArn":
      "acs:kms:us-west-1:0000111122223333:key/ed204e08-f814-4788-8406-3dc19c8e5260",
  },
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
      'AutomaticRotation': "Disabled",
    },
  },
];

const createCache = (
  disksData,
  listKeys,
  describeKeyData,
  disksErr,
  listKeysErr,
  describeKeyErr
) => {
  let keyId = listKeys && listKeys.length ? listKeys[0].KeyId : null;
  let keyData = describeKeyData && describeKeyData.length ? describeKeyData[0].data : null;
  return {
    ecs: {
      DescribeDisks: {
        "cn-hangzhou": {
          data: disksData,
          err: disksErr,
        },
      },
    },
    kms: {
      ListKeys: {
        "cn-hangzhou": {
          data: listKeys,
          err: listKeysErr,
        },
      },
      DescribeKey: {
        "cn-hangzhou": {
          [keyId]: {
            data: keyData,
            err: describeKeyErr,
          },
        },
      },
    },
  };
};

const system_disks_encryption_level = "alibabacmk";
const system_disks_result_limit = "0";

describe("systemDisksEncrypted", function () {
  describe("run", function () {
    
    it("should PASS if System disks are encrypted", function (done) {
      const cache = createCache([describeDisks[1]], listKeys);
      systemDisksEncrypted.run(cache, {}, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].message).to.include("System disk is encrypted to at least cloudkms");
        expect(results[0].status).to.equal(0);
        expect(results[0].region).to.equal("cn-hangzhou");
        done();
      });
    });

    it("should PASS if System disks are encrypted to target encryption level", function (done) {
      const cache = createCache([describeDisks[2]], listKeys, describeKey);
      systemDisksEncrypted.run(cache, { system_disks_encryption_level }, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].message).to.include(`System disk is encrypted to at least ${system_disks_encryption_level}`);
        expect(results[0].status).to.equal(0);
        expect(results[0].region).to.equal("cn-hangzhou");
        done();
      });
    });

    it("should FAIL if disk is not encrypted", function (done) {
      const cache = createCache([describeDisks[3]], listKeys);
      systemDisksEncrypted.run(cache, {}, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include("System disk is not encrypted to cloudkms");
        expect(results[0].region).to.equal("cn-hangzhou");
        done();
      });
    });

    it("should FAIL if System disk is not encrypted to target encryption level", function (done) {
      const cache = createCache([describeDisks[3]], listKeys);
      systemDisksEncrypted.run(
        cache, { system_disks_encryption_level },
        (err, results) => {
          expect(results.length).to.equal(1);
          expect(results[0].status).to.equal(2);
          expect(results[0].message).to.include(`System disk is not encrypted to ${system_disks_encryption_level}`);
          expect(results[0].region).to.equal("cn-hangzhou");
          done();
        }
      );
    });



    it("should FAIL if System disk is not encrypted to target level and combine results when reach results limit", function (done) {
      const cache = createCache([describeDisks[3]], listKeys, describeKey);
      systemDisksEncrypted.run(
        cache,
        {
          system_disks_encryption_level,
          system_disks_result_limit,
        },
        (err, results) => {
          expect(results.length).to.equal(1);
          expect(results[0].status).to.equal(2);
          expect(results[0].message).to.include(`More than ${system_disks_result_limit} system disks are not encrypted to ${system_disks_encryption_level}`);
          expect(results[0].region).to.equal("cn-hangzhou");
          done();
        }
      );
    });

    it("should PASS if no ECS disks found", function (done) {
      const cache = createCache([]);
      systemDisksEncrypted.run(cache, {}, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include("No ECS disks found");
        expect(results[0].region).to.equal("cn-hangzhou");
        done();
      });
    });

    it("should UNKNOWN if unable to query ECS disks", function (done) {
      const cache = createCache([], null, null, {
        err: "Unable to query ECS disks",
      });
      systemDisksEncrypted.run(cache, {}, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(3);
        expect(results[0].message).to.include("Unable to query ECS disks");
        expect(results[0].region).to.equal("cn-hangzhou");
        done();
      });
    });
  });
});
