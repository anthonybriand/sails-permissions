var actionMethodMap = {
  find: 'read',
  findOne: 'read',
  create: 'create',
  update: 'update',
  delete: 'delete'
};

module.exports = {

  /**
   * Query the ownership relationship between a user and an object.
   *
   * @returns {Integer}
   *  0   user is the the owner of the object, e.g. user = object.owner;
   *  1   user can reach the owner of the object via one Role
   *  -1 there is no Role subgraph that connects the user to object.owner
   */
  getOwnership: function (user, object) {
    return user.getOwnershipRelation(object);
  },

  /**
   * Given an action, return the CRUD method it maps to.
   */
  getMethod: function (req) {
    return actionMethodMap[req.options.action];
  },

  checkPermissions: function (user, model, method) {
  }
};