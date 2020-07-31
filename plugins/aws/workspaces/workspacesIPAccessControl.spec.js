var assert = require("assert");
var expect = require("chai").expect;
var metrics = require("./workspacesIPAccessControl.js")

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

        it("should give an output of no available workspaces", function (done) {
            const settings = {};
            const cache = noWorkspaces();

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            };

            metrics.run(cache, settings, callback);
            done();
        });

        it("should give no IP access controls on both the workspaces", function (done) {
            const settings = {};
            const cache = testWorkspaces();

            const callback = (err, results) => {
                console.log(results)
                expect(results.length).to.equal(3)
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
                expect(results[2].status).to.equal(0);
            };

            metrics.run(cache, settings, callback);
            done();
        })

        it("should give missing metric for a metric that is defined with all requirements", function (done) {
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
                            DirectoryId: "d-01",
                        },
                        {
                            WorkspaceId: "test02",
                            DirectoryId: "d-02",
                        },
                    ]
                },
            },
            describeWorkspaceDirectories: {
                "us-east-1":{
                    data:[
                        {
                            DirectoryId: "d-01",
                            DirectoryName: "corp.amazonworkspaces.com",
                            CustomerUserName: "Administrator",
                            ipGroupIds: [
                                "ipgroup01"
                            ]
                        },
                        {
                            DirectoryId: "d-02",
                            DirectoryName: "corp.amazonworkspaces.com",
                            CustomerUserName: "Administrator",
                            ipGroupIds: [
                                "ipgroup02",
                                "ipgroup03"
                            ]
                        }
                    ]
                }
            },
            describeIpGroups:{
                "us-east-1":{
                    data: [
                        {
                            "groupId": "ipgroup01",
                            "groupName": "testIPControlAccess"
                        },
                        {
                            "groupId": "ipgroup02",
                            "groupName": "testIPControlAccess"
                        },
                        {
                            "groupId": "ipgroup03",
                            "groupName": "testIPControlAccess",
                            "userRules": [
                                {
                                    "ipRule": "192.45.32.10",
                                    "ruleDesc": "Open for one."
                                }
                            ]
                        }
                    ]
                }
            }
        },
    }
};

const testWorkspaces2 = (statement) => {
    return {workspaces:{
            describeWorkspaces: {
                "us-east-1":{
                    data: [
                        {
                            WorkspaceId: "test01",
                            DirectoryId: "d-01",
                        },
                        {
                            WorkspaceId: "test02",
                            DirectoryId: "d-02",
                        },
                    ]
                },
            },
            describeWorkspaceDirectories: {
                "us-east-1":{
                    data:[
                        {
                            DirectoryId: "d-01",
                            DirectoryName: "corp.amazonworkspaces.com",
                            CustomerUserName: "Administrator",
                            ipGroupIds: [
                                "ipgroup01"
                            ]
                        },
                        {
                            DirectoryId: "d-02",
                            DirectoryName: "corp.amazonworkspaces.com",
                            CustomerUserName: "Administrator",
                            ipGroupIds: [
                                "ipgroup02"
                            ]
                        }
                    ]
                }
            },
            describeIpGroups:{
                "us-east-1":{
                    data: [
                        {
                            "groupId": "ipgroup01",
                            "groupName": "testIPControlAccess"
                        },
                        {
                            "groupId": "ipgroup02",
                            "groupName": "testIPControlAccess",
                            "userRules": [
                                {
                                    "ipRule": "0.0.0.0/0",
                                    "ruleDesc": "Open for all"
                                }
                            ]
                        }
                    ]
                }
            }
        },
    }
};

