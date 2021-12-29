
var expect = require('chai').expect;
var workspacesDesiredBundleType = require('./workspacesDesiredBundleType.js');

const describeWorkspaces = [
    {
        WorkspaceId: 'ws-f7hsrphp6',
        DirectoryId: 'd-9067552532',
        UserName: 'test',
        IpAddress: '172.16.1.134',
        State: 'AVAILABLE',
        BundleId: 'wsb-clj85qzj1',
        SubnetId: 'subnet-017fd5eda595ac73f',
        ComputerName: 'test',
        WorkspaceProperties: {
            RunningMode: 'AUTO_STOP',
            RunningModeAutoStopTimeoutInMinutes: 60,
            RootVolumeSizeGib: 80,
            UserVolumeSizeGib: 50,
            ComputeTypeName: 'STANDARD'
        },
        ModificationStates: []
    },
    {
        WorkspaceId: 'ws-f7hsrphp6',
        DirectoryId: 'd-9067552532',
        UserName: 'test',
        IpAddress: '172.16.1.134',
        State: 'AVAILABLE',
        BundleId: 'wsb-clj85qzj1',
        SubnetId: 'subnet-017fd5eda595ac73f',
        ComputerName: 'test',
        WorkspaceProperties: {
            RunningMode: 'AUTO_STOP',
            RunningModeAutoStopTimeoutInMinutes: 60,
            RootVolumeSizeGib: 80,
            UserVolumeSizeGib: 50,
            ComputeTypeName: 'PERFORMANCE'
        },
        ModificationStates: []
    },
];

const createCache = (data, err) => {
    return {
        workspaces: {
          describeWorkspaces: {
                'us-east-1': {
                    data: data,
                    err: err
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        workspaces: {
            describeWorkspaces: {
                'us-east-1': {
                    data: [],
                    err: {
                        message: 'error describing workspaces'
                    },
                }
            }
        }
    };
};

describe('workspacesDesiredBundleType', function () {
    describe('run', function () {
        it('should PASS if no workspace instances found', function (done) {
            const cache = createCache([]);
            workspacesDesiredBundleType.run(cache, { workspace_desired_bundle_type: 'PERFORMANCE' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if Unable to query for WorkSpaces instances', function (done) {
            const cache = createErrorCache();
            workspacesDesiredBundleType.run(cache, { workspace_desired_bundle_type: 'PERFORMANCE' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should PASS if the Workspace is using desired bundle type', function (done) {
            const cache = createCache([describeWorkspaces[1]]);
            workspacesDesiredBundleType.run(cache, { workspace_desired_bundle_type: 'PERFORMANCE, STANDARD' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Workspace is not using desired bundle type', function (done) {
            const cache = createCache([describeWorkspaces[1]]);
            workspacesDesiredBundleType.run(cache, { workspace_desired_bundle_type: 'STANDARD' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
