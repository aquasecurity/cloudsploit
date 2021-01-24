var parse = function(obj, path) {
    if (typeof path == 'string') path = path.split('.');
    if (Array.isArray(path) && path.length) {
        var localPath = path.shift();
        if (obj[localPath]) {
            return parse(obj[localPath], path);
        } else {
            return 'not set';
        }
    } else {
        return obj;
    }
};

var transform = function(val, transformation) {
    if (transformation == 'DATE') {
        return new Date(val);
    } else if (transformation == 'INTEGER') {
        return parseInt(val);
    } else if (transformation == 'STRING') {
        return val.toString();
    } else if (transformation == 'DAYSFROM') {
        // Return the number of days between the date and now
        var now = new Date();
        var then = new Date(val);
        var timeDiff = then.getTime() - now.getTime();
        var diff = Math.round(timeDiff / (1000 * 3600 * 24));
        return diff;
    } else if (transformation == 'COUNT') {
        return val.length;
    } else if (transformation == 'EACH') {
        return val;
    } else {
        return val;
    }
};

var validate = function(obj, conditions) {
    var result = 0;
    var message = [];
    var override = false;

    // Extract the values for the conditions
    conditions.forEach(function(condition) {
        if (condition.property) {
            var conditionResult = 0;
            condition.parsed = parse(obj, condition.property);

            // Transform the property if required
            if (condition.transform) {
                condition.parsed = transform(condition.parsed, condition.transform);
            }

            // Compare the property with the operator
            if (condition.op) {
                if (condition.op == 'EQ') {
                    if (condition.parsed == condition.value) {
                        message.push(`${condition.property}: ${condition.parsed} matched: ${condition.value}`);
                    } else {
                        conditionResult = 2;
                        message.push(`${condition.property}: ${condition.parsed} did not match: ${condition.value}`);
                    }
                } else if (condition.op == 'GT') {
                    if (condition.parsed > condition.value) {
                        message.push(`${condition.property}: count of ${condition.parsed} was greater than: ${condition.value}`);
                    } else {
                        conditionResult = 2;
                        message.push(`${condition.property}: count of ${condition.parsed} was not greater than: ${condition.value}`);
                    }
                } else if (condition.op == 'NE') {
                    if (condition.parsed !== condition.value) {
                        message.push(`${condition.property}: ${condition.parsed} is not: ${condition.value}`);
                    } else {
                        conditionResult = 2;
                        message.push(`${condition.property}: ${condition.parsed} is: ${condition.value}`);
                    }
                }
            } else if (condition.transform && condition.transform == 'EACH' && condition.conditions) {
                // Recurse into the same function
                var subProcessed = [];
                condition.parsed.forEach(function(parsed) {
                    subProcessed.push(validate(parsed, condition.conditions));
                });
                subProcessed.forEach(function(sub) {
                    if (sub.status) conditionResult = sub.status;
                    if (sub.message) message.push(sub.message);
                });
            }
            if (condition.invert) conditionResult = (conditionResult ? 0 : 2);

            if (condition.override && !conditionResult) override = true;
            if (conditionResult) result = conditionResult;
        }
    });

    if (result && override) result = 0;

    if (!message.length) {
        message = ['The resource matched all required conditions'];
    }

    return {
        status: result,
        message: message.join(', ')
    };
};

var gsl = function(source, input, resourceMap, callback) {
    if (!source || !input) return callback('No source or input provided');
    if (!input.apis || !input.apis[0]) return callback('No APIs provided for input');
    if (!input.conditions || !input.conditions.length) return callback('No conditions provided for input');

    // Split apis into service:api
    // TODO: support conditions that use different APIs
    var service = input.conditions[0].service;
    var api = input.conditions[0].api;
    var resourcePath;
    if (resourceMap &&
        resourceMap[service] &&
        resourceMap[service][api]) {
        resourcePath = resourceMap[service][api];
    }

    if (!source[service]) return callback(`Source data did not contain service: ${service}`);
    if (!source[service][api]) return callback(`Source data did not contain API: ${api}`);

    var results = [];

    for (var region in source[service][api]) {
        var regionVal = source[service][api][region];
        if (typeof regionVal !== 'object') continue;
        if (regionVal.err) {
            results.push({
                status: 3,
                message: regionVal.err.message || 'Error',
                region: region
            });
        } else if (regionVal.data) {
            // It's an array, loop
            regionVal.data.forEach(function(regionData) {
                var validated = validate(regionData, input.conditions);
                var parsedResource = parse(regionData, resourcePath);
                if (typeof parsedResource !== 'string') parsedResource = null;

                results.push({
                    status: validated.status,
                    resource: parsedResource,
                    message: validated.message,
                    region: region
                });
            });
        } else {
            for (var resourceName in regionVal) {
                var resourceObj = regionVal[resourceName];
                if (resourceObj.err) {
                    results.push({
                        status: 3,
                        resource: resourceName,
                        message: resourceObj.err.message || 'Error',
                        region: region
                    });
                } else if (!resourceObj.data) {
                    results.push({
                        status: 3,
                        resource: resourceName,
                        message: 'No data returned',
                        region: region
                    });
                } else {
                    var validated = validate(resourceObj.data, input.conditions);
                    var parsedResource = parse(resourceObj.data, resourcePath);
                    if (typeof parsedResource !== 'string') parsedResource = null;

                    results.push({
                        status: validated.status,
                        resource: parsedResource,
                        message: validated.message,
                        region: region
                    });
                }
            }
        }
    }

    callback(null, results, source[service][api]);
};

module.exports = gsl;
