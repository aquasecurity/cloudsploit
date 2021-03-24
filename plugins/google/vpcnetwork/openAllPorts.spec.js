var expect = require('chai').expect;
const openAllPorts = require('./openAllPorts');

const firewalls = [
    {
        "id": "4111718641158512144",
        "creationTimestamp": "2021-02-25T00:34:07.519-08:00",
        "name": "openall",
        "description": "Open All Ports",
        "network": "https://www.googleapis.com/compute/v1/projects/aqua-dev-akhtar/global/networks/app-vpc",
        "priority": 1000,
        "sourceRanges": [ "0.0.0.0/0" ],
        "allowed": [{ "IPProtocol": "all" }],
        "direction": "INGRESS",
        "disabled": false,
        "selfLink": "https://www.googleapis.com/compute/v1/projects/aqua-dev-akhtar/global/firewalls/openall",
        "kind": "compute#firewall"
    },
    {
        "id": "3482752052453535354",
        "creationTimestamp": "2021-02-25T00:34:07.519-08:00",
        "name": "opensome",
        "description": "",
        "network": "https://www.googleapis.com/compute/v1/projects/aqua-dev-akhtar/global/networks/app-vpc",
        "priority": 1000,
        "sourceRanges": [ "192.168.0.0/16" ],
        "allowed": [{ "IPProtocol": "tcp", "ports": [ "22" ] }],
        "direction": "INGRESS",
        "disabled": false,
        "selfLink": "https://www.googleapis.com/compute/v1/projects/aqua-dev-akhtar/global/firewalls/opensome",
        "kind": "compute#firewall"
    }
];

const createCache = (groups, err) => {
    return {
        firewalls:{
            list: {
                'global': {
                    data: groups,
                    err: err
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        firewalls:{
            list: {
                'global': null,
            },
        },
    };
};

describe('openAllPorts', function () {
    describe('run', function () {
        it('should PASS if no open ports found', function (done) {
            const cache = createCache([firewalls[1]]);
            openAllPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if firewall rule has all ports open to public', function (done) {
            const cache = createCache([firewalls[0]]);
            openAllPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should PASS if no firewall rules found', function (done) {
            const cache = createCache([]);
            openAllPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should UNKNWON if unable to describe firewall rules', function (done) {
            const cache = createCache([], { message: 'Unable to query firewall rules'});
            openAllPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should not return anything if describe firewall rules response not found', function (done) {
            const cache = createNullCache();
            openAllPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
