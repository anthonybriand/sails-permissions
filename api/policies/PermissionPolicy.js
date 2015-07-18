var Promise = require('bluebird');
/**
 * PermissionPolicy
 * @depends OwnerPolicy
 * @depends ModelPolicy
 *
 * In order to proceed to the controller, the following verifications
 * must pass:
 * 1. User is logged in (handled previously by sails-auth sessionAuth policy)
 * 2. User has Permission to perform action on Model
 * 3. User has Permission to perform action on Attribute (if applicable) [TODO]
 * 4. User is satisfactorily related to the Object's owner (if applicable)
 *
 * This policy verifies #1-2 here, before any controller is invoked. However
 * it is not generally possible to determine ownership relationship until after
 * the object has been queried. Verification of #4 occurs in RolePolicy.
 *
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
module.exports = function (req, res, next) {
  var options = {
    model: req.model,
    method: req.method,
    user: req.user,
    object: (req.params.id) ? {id: req.params.id} : -1
  };

  if (req.options.unknownModel) {
    return next();
  }

  PermissionService
    .findModelPermissions(options)
    .then(function (permissions) {
      sails.log.silly('PermissionPolicy:', permissions.length, 'permissions grant',
          req.method, 'on', req.model.name, 'for', req.user.username);

      if (options.method == "GET" && options.object == -1 && _.isObject(req.query) && Object.keys(req.query).length > 0) {
        req.permissions = permissions;
        bindResponsePolicyDenied(req, res);

        next();
      } else {
        PermissionService.isDenied(options)
          .then(function (denied) {
            if (!permissions || permissions.length === 0 || (denied && denied.length > 0)) {
              return res.badRequest({ error: PermissionService.getErrorMessage(options) });
            }

            req.permissions = permissions;
            bindResponsePolicyDenied(req, res);

            next();
          });
      }
    });
};

function bindResponsePolicy (req, res) {
  res._ok = res.ok;

  res.ok = _.bind(responsePolicy, {
    req: req,
    res: res
  });
}

function responsePolicy (_data, options) {
  var req = this.req;
  var res = this.res;
  var user = req.owner;
  var method = PermissionService.getMethod(req);

  var data = _.isArray(_data) ? _data : [_data];

  //sails.log('data', _data);
  //sails.log('options', options);

  // TODO search populated associations
  Promise.bind(this)
    .map(data, function (object) {
      return user.getOwnershipRelation(data);
    })
    .then(function (results) {
      //sails.log('results', results);
      var permitted = _.filter(results, function (result) {
        return _.any(req.permissions, function (permission) {
          return permission.permits(result.relation, method);
        });
      });

      if (permitted.length === 0) {
        //sails.log('permitted.length === 0');
        return res.send(404);
      }
      else if (_.isArray(_data)) {
        return res._ok(permitted, options);
      }
      else {
        res._ok(permitted[0], options);
      }
    });
}

function bindResponsePolicyDenied(req, res) {
  res.__ok = res.ok;

  res.ok = _.bind(deniedPolicy, {
    req: req,
    res: res
  });
}

function deniedPolicy(_data, options) {
  var req = this.req;
  var res = this.res;
  var opts = {
    model: req.model,
    method: req.method,
    user: req.user,
    body: req.body
  };

  var data = _.isArray(_data) ? _data : [_data];

  //sails.log('data', _data);
  //sails.log('options', options);

  var results = [];
  Promise.map(data, function (object) {
    return new Promise(function (resolveDenied, rejectDenied) {
      if (object) {
        var clOpts = _.clone(opts);
        clOpts.object = object;
        PermissionService.isDenied(clOpts)
          .then(function (permissions) {
            if (!permissions || permissions.length === 0) {
              results.push(object);
            }

            resolveDenied();
          }).catch(rejectDenied);
      } else {
        results.push(object);
        resolveDenied();
      }
    });
  }).then(function () {
    if (results.length === 0 && !_.isArray(_data)) {
      //sails.log('permitted.length === 0');
      return res.send(404);
    }
    else if (_.isArray(_data)) {
      return res.__ok(results, options);
    }
    else {
      res.__ok(results[0], options);
    }
  }).catch(res.negotiate);
}