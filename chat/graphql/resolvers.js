const bcrypt = require('bcryptjs')
const { UserInputError , AuthenticationError} = require('apollo-server')

const { User } = require('../models')

module.exports = {
  Query: {
    getUsers: async () => {
      try {
        const users = await User.findAll()

        return users
      } catch (err) {
        console.log(err)
      }
    },
    login: async (_, args) => {
      const {username, password} = args
      let errors = {}

      try {
        const user = await User.findOne({
          where: {username}
        })

        if (!user){
          errors.username = 'user not found'
          throw new UserInputError('user not found', {errors})
        }

        const correctPassword = await bcrypt.compare(password, user.password)

        if(!correctPassword){
          errors.password = 'password is incorrect'
          throw new AuthenticationError('password is incorrect', { errors })
        }
        return user
      } catch(err){
        console.log(err)
        throw err
      }
    }
  },
  Mutation: {
    register: async (_, args) => {
      let { username, email, password, confirmPassword } = args
      let errors = {}

      try {
        if (email.trim() === '') errors.email = 'email must not be empty'
        if (username.trim() === '')
          errors.username = 'username must not be empty'
        if (password.trim() === '')
          errors.password = 'password must not be empty'
        if (confirmPassword.trim() === '')
          errors.confirmPassword = 'repeat password must not be empty'

        if (password !== confirmPassword)
          errors.confirmPassword = 'passwords must match'
          
        if (Object.keys(errors).length > 0) {
          throw errors
        }

        // Hash password
        password = await bcrypt.hash(password, 6)

        // Create user
        const user = await User.create({
          username,
          email,
          password,
        })

        return user
      } catch (err) {
        console.log(err)
        if (err.name === 'SequelizeUniqueConstraintError') {
          err.errors.forEach(
            (e) => (errors[e.path] = `${e.path} is already taken`)
          )
        } else if (err.name === 'SequelizeValidationError') {
          err.errors.forEach((e) => (errors[e.path] = e.message))
        }
        throw new UserInputError('Bad input', { errors })
      }
    },
  },
}