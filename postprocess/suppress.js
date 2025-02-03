module.exports = {
    create: function(suppressions) {
        // Creates an object that can post process results to suppress rules
        // This allows the client to set to ignore particular failures so that
        // they don't affect the overall score
        // Suppressions have the format pluginId:region:resourceId, where any
        // of the items can be * to indicate match all.
        if (!suppressions) suppressions = [];

        // Validate suppression format
        const validateSuppression = (expr) => {
            // Check basic format (three parts separated by colons)
            const parts = expr.split(':');
            if (parts.length !== 3) {
                throw new Error(`Invalid suppression format: ${expr}. Expected format: pluginId:region:resourceId`);
            }

            // Define allowed characters for each part
            const allowedPluginIdChars = /^[a-zA-Z0-9_*-]{1,64}$/;
            const allowedRegionChars = /^[a-zA-Z0-9_*-]{1,32}$/;
            const allowedResourceIdChars = /^[a-zA-Z0-9_*\/-]{1,128}$/;

            const [pluginId, region, resourceId] = parts;

            // Validate each part
            if (!allowedPluginIdChars.test(pluginId)) {
                throw new Error(`Invalid pluginId in suppression: ${pluginId}. Only alphanumeric, underscore, hyphen, and * are allowed.`);
            }
            if (!allowedRegionChars.test(region)) {
                throw new Error(`Invalid region in suppression: ${region}. Only alphanumeric, underscore, hyphen, and * are allowed.`);
            }
            if (!allowedResourceIdChars.test(resourceId)) {
                throw new Error(`Invalid resourceId in suppression: ${resourceId}. Only alphanumeric, underscore, hyphen, forward slash, and * are allowed.`);
            }

            return true;
        };

        // Validate and create expressions
        var expressions = suppressions
            .map(function(expr) {
                // Validate the expression format
                validateSuppression(expr);

                // Escape special regex characters except * which we handle specially
                const escapedExpr = expr
                    .replace(/[.+?^${}()|[\]\\]/g, '\\$&') // Escape special regex chars
                    .split('*')
                    .join('.*'); // Replace * with .*

                return [
                    expr,
                    new RegExp('^' + escapedExpr + '$')
                ];
            });

        return function(result) {
            var match = expressions.find(function(expression) {
                return expression[1].test(result);
            });

            return match && match[0];
        };
    }
};
