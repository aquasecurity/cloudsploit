var expect = require("chai").expect;
var metrics = require("./workspacesVolumeEncryption.js")


const errorWorkspaces = (statement) => {
    return {workspaces:{
            describeWorkspaces: {
                "us-east-1":{
                },
            },
        },
    }
};

const noWorkspaces = (statement) => {
    return {workspaces:{
            describeWorkspaces: {
                "us-east-1":{
                    data: []
                },
            },
        },
        kms:{describeKey: {"us-east-1":{data: []}},
            listKeys: {"us-east-1":{data:[]}},}
    }
};

const testWorkspaces = (statement) => {
    return {workspaces:{describeWorkspaces: {"us-east-1":{data: [
        {
            WorkspaceId: "test01",
            UserVolumeEncryptionEnabled: true,
            RootVolumeEncryptionEnabled: true,
            VolumeEncryptionKey: "arn:aws:kms:us-east-1:null:key/12345"
        },
        {
            WorkspaceId: "test02",
            RootVolumeEncryptionEnabled: true,
            VolumeEncryptionKey: "arn:aws:kms:us-east-1:null:key/12345"
        },]},},},
        kms:{describeKey: {"us-east-1":{"12345": {data: {KeyMetadata:{
                            KeyId: "12345",
                            Arn: "arn:aws:kms:us-east-1:null:key/12345",
                            KeyState: "Enabled",
                            Origin: "AWS_KMS",
                            KeyManager: "AWS",
                        }
        }}}},
            listKeys: {"us-east-1":{data:[{
                        "KeyId": "12345",
                        "KeyArn": "arn:aws:kms:us-east-1:null:key/12345"}]}},}
    }};

const testWorkspaces2 = (statement) => {
    return {workspaces:{
            describeWorkspaces: {"us-east-1":{data: [
                {
                    WorkspaceId: "test01",
                    UserVolumeEncryptionEnabled: true,
                    RootVolumeEncryptionEnabled: true,
                    VolumeEncryptionKey: "arn:aws:kms:us-east-1:null:key/12345"
                },]},},
        },
        kms:{describeKey: {"us-east-1": {12345: {data: {KeyMetadata:{
                            KeyId: "12345",
                            Arn: "arn:aws:kms:us-east-1:null:key/12345",
                            KeyState: "Enabled",
                            Origin: "AWS_KMS",
                            KeyManager: "AWS",
                        }
        }}}},
            listKeys: {"us-east-1":{data:[{
                        "KeyId": "12345",
                        "KeyArn": "arn:aws:kms:us-east-1:null:key/12345"}]}},}
    }};


describe("workspacesVolumeEncryption", function () {
    describe("run", function () {
        it("should give a general error if it can not get workspaces", function (done) {
            const settings = {};
            const cache = errorWorkspaces();
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
            };

            metrics.run(cache, settings, callback);
            done();
        });

        it("should give an output of no workspaces found", function (done) {
            const settings = {};
            const cache = noWorkspaces();

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            };

            metrics.run(cache, settings, callback);
            done();
        });

        it("should give volume encryption enabled for first workspace and not enabled on second workspace", function (done) {
            const settings = {};
            const cache = testWorkspaces();

            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(2);
            };

            metrics.run(cache, settings, callback);
            done();
        })

        it("should give a fail because the current encryption level is lower than desired", function (done) {
            const cache = testWorkspaces2();

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
            };

            metrics.run(cache, {workspace_encryption_level: "externalcmk"}, callback);
            done();
        })
    })
})