var expect = require("chai").expect;
var metrics = require("./workspacesOperationalState.js")


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
    return {workspaces:{describeWorkspaces: {"us-east-1":{data: [
                        {
                            WorkspaceId: "test01",
                            State: "UNHEALTHY"
                        },
                        {
                            WorkspaceId: "test02",
                            State: "AVAILABLE"
                        },]},},},
    }};

const testWorkspaces2 = (statement) => {
    return {workspaces:{
            describeWorkspaces: {"us-east-1":{data: [
                        {
                            WorkspaceId: "test01",
                            State: "STOPPED"
                        },]},},
        },
    }};

describe("workspacesOperationalState", function () {
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

        it("should give unhealthy state for first workspace and available on second workspace", function (done) {
            const settings = {};
            const cache = testWorkspaces();

            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(0);
            };

            metrics.run(cache, settings, callback);
            done();
        })

        it("should give a stopped state for only workspace", function (done) {
            const settings = {};
            const cache = testWorkspaces2();

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            };

            metrics.run(cache, settings, callback);
            done();
        })
    })
})