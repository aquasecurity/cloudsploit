const expect = require('chai').expect;
const enableDetailedMonitoring = require('./enableDetailedMonitoring');

describeInstances = [
	{
		Groups: [],
		Instances: [
			{
				AmiLaunchIndex: 0,
				ImageId: 'ami-0022f774911c1d690',
				InstanceId: 'i-02d03efaa61cec2b4',
				InstanceType: 't2.micro',
				KeyName: 'test',
				LaunchTime: '2022-06-21T13:19:06+00:00',
				Monitoring: {
					State: 'disabled'
				}
			}
		]
	},
	{
		Groups: [],
		Instances: [
			{
				AmiLaunchIndex: 0,
				ImageId: 'ami-026b57f3c383c2eec',
				InstanceId: 'i-014684b238c2a2542',
				InstanceType: 't2.micro',
				KeyName: 'key',
				LaunchTime: '2022-09-23T08:04:24+00:00',
				Monitoring: {
					State: 'enabled'
				}
			}
		],
		OwnerId: '000011112222',
		ReservationId: 'r-065644dc06b2b1443'
	}

];

const createCache = (instances) => {
	return {
		ec2: {
			describeInstances: {
				'us-east-1': {
					data: instances
				}
			}
		}
	};
};

const createErrorCache = () => {
	return {
		ec2: {
			describeInstances: {
				'us-east-1': {
					err: {
						message: 'error'
					}
				}
			}
		}
	};
};

describe('enableDetailedMonitoring', function () {
	describe('run', function () {
		it('should PASS if there are no instances', function (done) {
			const cache = createCache([]);
			enableDetailedMonitoring.run(cache, {}, (err, results) => {
				expect(results.length).to.equal(1);
				expect(results[0].status).to.equal(0);
				expect(results[0].region).to.equal('us-east-1');
				expect(results[0].message).to.include('No EC2 instances found');
				done();
			});
		});

		it('should UNKNOWN if describeInstances error', function (done) {
			const cache = createErrorCache();
			enableDetailedMonitoring.run(cache, {}, (err, results) => {
				expect(results.length).to.equal(1);
				expect(results[0].status).to.equal(3);
				expect(results[0].message).to.include('Unable to query for instances');
				done();
			});
		});

		it('should PASS if EC2 instance has enabled detailed monitoring', function (done) {
			const cache = createCache([describeInstances[1]]);
			enableDetailedMonitoring.run(cache, {}, (err, results) => {
				expect(results.length).to.equal(1);
				expect(results[0].status).to.equal(0);
				expect(results[0].region).to.equal('us-east-1');
				expect(results[0].message).to.equal( 'Instance has enabled detailed monitoring');
				done();
			});
		});

		it('should FAIL if EC2 instance does not have enabled detailed monitoring', function (done) {
			const cache = createCache([describeInstances[0]]);
			enableDetailedMonitoring.run(cache, {}, (err, results) => {
				expect(results.length).to.equal(1);
				expect(results[0].status).to.equal(2);
				expect(results[0].region).to.equal('us-east-1');
				expect(results[0].message).to.equal( 'Instance does not have enabled detailed monitoring');
				done();
			});
		});
	});
});
