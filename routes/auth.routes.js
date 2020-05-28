const {Router} = require('express')
const crypt = require('bcrypt');
//const bart = require('bcryptjs')
const config = require('config')
const jwt = require('jsonwebtoken')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()

// /api/auth/register
router.post(
    '/register',
    [
        check('email', 'Некорректный e-mail').isEmail(),
        check('password', 'Пароль минимум 6 символов')
            .isLength({min:6})
    ],
    async (req, res) =>{
    try{
        const errors = validationResult(req)

        if (!errors.isEmpty()){
            return res.status(400).json({
                errors: errors.array(),
                message: 'Некорректные данные при регистрации'
            })
        }

        const {email, password} = req.body

        const candidate = await User.findOne({ email })

        if (candidate){
           return  res.status(400).json({message:'Такой пользователь уже существует'})
        }

        const hashedPassword = await crypt.hash(password, 12)
        const user = new User({email, password: hashedPassword})

        await user.save()

        res.status(201).json({ message: 'Пользователь успешно зарегистрирован'})

    }   catch (e) {
        res.status(500).json({ message: 'Что-то пошло не так, попробуйте снова'})
    }
})

// /api/auth/login
router.post(
    '/login',
    [
        check('email', 'Введите корректный email').normalizeEmail().isEmail(),
        check('password', 'Введите пароль').exists()
    ],
    async (req, res) =>{
    try{
        const errors = validationResult(req)

        if (!errors.isEmpty()){
            return res.status(400).json({
                errors: errors.array(),
                message: 'Некорректные данные при входе в систему'
            })
        }

        const {email, password} = req.body

        const user = await User.findOne({ email })

        if (!user){
            return res.status(400).json({ message:'Пользователь не найден'})
        }

        const isMatch = await crypt.compare(password, user.password)

        if (!isMatch){
            return res.status(400).json({message:"Неверный пароль, попробуйте снова"})
        }

        const token = jwt.sign(
            {userId: user.id},
            config.get('jwtSecret'),
            {expiresIn: '1h'}
        )

        res.json({token, userId:user.id})

    }   catch (e) {
        res.status(500).json({message: 'Что-то пошло не так, попробуйте снова'})
    }
})

module.exports  = router