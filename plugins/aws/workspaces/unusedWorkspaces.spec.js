var expect = require('chai').expect;
var unusedWorkspaces = require('./unusedWorkspaces.js');

const describeWorkspacesConnectionStatus = [
    {
        WorkspaceId: "test01",
        ConnectionState: "CONNECTED",
        ConnectionStateCheckTimestamp:"2021-10-04T08:56:18.935Z",
        LastKnownUserConnectionTimestamp: new Date()
    },
    {
        WorkspaceId: "test02",
        ConnectionState:"DISCONNECTED",
        ConnectionStateCheckTimestamp:"2021-10-04T08:56:18.935Z",
        LastKnownUserConnectionTimestamp: "2020-10-04T08:56:18.935Z"
    },
    {
        WorkspaceId: "test02",
        ConnectionState:"DISCONNECTED",
        ConnectionStateCheckTimestamp:"2021-10-04T08:56:18.935Z"
    },
    
];

const createCache = (data, err) => {
    return {
        workspaces: {
            describeWorkspacesConnectionStatus: {
                'us-east-1': {
                    data: data,
                    err: err
                }
            }
        }
    };
};

describe('unusedWorkspaces', function () {
    describe('run', function () {
        it('should PASS if no workspace connection found', function (done) {
            const cache = createCache([]);
            unusedWorkspaces.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should UNKNOWN if Unable to query for WorkSpaces instance connection status', function (done) {
            const cache = createCache(null,"");
            unusedWorkspaces.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        it('should PASS if Workspace is in use', function (done) {
            const cache = createCache([describeWorkspacesConnectionStatus[0]]);
            unusedWorkspaces.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Workspace is not in use for last 30 days', function (done) {
            const cache = createCache([describeWorkspacesConnectionStatus[1]]);
            unusedWorkspaces.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if WorkSpace does not have any known user connection', function (done) {
            const cache = createCache([describeWorkspacesConnectionStatus[2]]);
            unusedWorkspaces.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
