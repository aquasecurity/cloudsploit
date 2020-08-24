var assert = require("assert");
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
    }
};

const testWorkspaces = (statement) => {
    return {workspaces:{
            describeWorkspaces: {
                "us-east-1":{
                    data: [
                        {
                            WorkspaceId: "test01",
                            UserVolumeEncryptionEnabled: true,
                            RootVolumeEncryptionEnabled: true
                        },
                        {
                            WorkspaceId: "test02",
                            RootVolumeEncryptionEnabled: true
                        },
                    ]
                },
            },
        },
    }};

const testWorkspaces2 = (statement) => {
    return {workspaces:{
            describeWorkspaces: {
                "us-east-1":{
                    data: [
                        {
                            WorkspaceId: "test01"
                        },
                        {
                            WorkspaceId: "test02"
                        },
                    ]
                },
            },
        },
    }};


describe("workspacesIPAccessControl", function () {
    describe("run", function () {
        it("should give a general error if it can not get workspaces", function (done) {
            const settings = {};
            const cache = errorWorkspaces();
            const callback = (err, results) => {
                expect(results.length).to.equal(0)
            };
            metrics.run(cache, settings, callback);
            done();
        });

        it("should give an output of passed volume encryption on first workspace and no encryption on user volume for second workspace", function (done) {
            const settings = {};
            const cache = noWorkspaces();

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            };

            metrics.run(cache, settings, callback);
            done();
        });

        it("should give IP access controls on both the workspaces", function (done) {
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

        it("should give no volume encryption on both workspaces", function (done) {
            const settings = {};
            const cache = testWorkspaces2();

            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
            };

            metrics.run(cache, settings, callback);
            done();
        })
    })
})