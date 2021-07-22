const router = require("express").Router()
const bcryptjs = require("bcryptjs")
const mongoose = require("mongoose")

const User = require("./../models/User.model")

const { isLoggedIn, isLoggedOut } = require('./../middleware/route-guard')

router.get("/signup", isLoggedOut, (req, res) => {
  res.render("auth/signup")
})

router.post("/signup", (req, res) => {

  // EXTRACCION DE VALORES A UNA VARIABLE
  const { username, email, password } = req.body

  if (!username || !email || !password) {

    return res.render("auth/signup", {
      msg: "Todos los campos son obligatorios"
    })

  }

  // VERIFICAR QUE EL PASSWORD ES FUERTE (TIENE UNA COMBINACION DIFICIL)

  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;

  // SI EL PASSWORD NO CUMPLE CON REGEX
  if(!regex.test(password)) {
    return res.status(500).render("auth/signup", {
      msg: "Error: El password debe tener 6 caracteres mínimo y debe contener al menos un número, una minúscula y una mayúscula"
    })
  }



  // ENCRIPTACION
  bcryptjs
    .genSalt(10)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      return User.create({ 
        username, 
        email,  
        passwordHash: hashedPassword
      })
    })
    .then(usuarioCreado => {
      console.log("El usuario que creamos fue:", usuarioCreado)
      res.redirect('/userprofile')
    })

    // MENSAJE DE ERROR DE EMAIL INCORRECTO

    .catch(e => {
      if (e instanceof mongoose.Error.ValidationError) {
        res.status(500).render("auth/signup", {
          msg: "Error: Usa un email válido"
        })
      } else if (e.code === 11000) {
        res.status(500).render('auth/signup', {
          msg: "El usuario o el correo ya existe, intenta uno nuevo"
        })
      }
    })
})


// GET Profile Page for current User


// SI ESTOY LOGGEADO, PUEDO ENTRAR A USERPROFILE
// SI NO ESTOY LOGGEADO, ENVIAME A LA PAGINA LOGIN


router.get('/userprofile', isLoggedIn, (req, res) => {
  res.render("users/user-profile", { usuarioActual: req.session.usuarioActual })
})


// GET - Mostrar el formulario LOGIN

router.get('/login', (req, res) => {
  res.render("auth/login")
})


// POST - PROCESO DE AUTENTICACION
// VERIFICAR QUE EL USUARIO QUE ESTA PASANDO SU EMAIL Y CONTRASEÑA ES REALMENTE
// EL MISMO QUE SE REGISTRÓ

router.post("/login", (req, res) => {

  console.log(req.session)


  const { email, password } = req.body

  // VALIDAR EMAIL Y PASSWORD
  if (!email || !password) {
    return res.render("auth/login", {
      msg: "Por favor ingresa email y password."
    })
  }

  User.findOne({ email })
  .then((usuarioEncontrado) => {
    // 1. SI EL USUARIO NO EXISTE EN BASE DE DATOS
    if(!usuarioEncontrado){
      return res.render("auth/login", {
        msg: "El email no fue encontrado"
      })
    }
    const autenticacionVerificada = bcryptjs.compareSync(password, usuarioEncontrado.passwordHash)
    // 2. SI EL USUARIO SE EQUIVOCÓ EN LA CONTRASEÑA
    if(!autenticacionVerificada){
      return res.render("auth/login", {
        msg: "La contraseña es incorrecta"
      })
    }
    // 3. SI EL USUARIO COINCIDE LA CONTRASEÑA CON LA BASE DE DATOS

    // Vamos a crear en nuestro objeto SESSION una propiedad nueva que se llame usarioActual
    
    req.session.usuarioActual = usuarioEncontrado

    console.log("Sesión actualizada:", req.session)


    return res.redirect("/userprofile")
  })
  .catch((e) => console.log(e))


})

// POST - CERRAR SESION

router.post("/logout", (req, res) => {
  req.session.destroy(err => {
    if(err) {
      console.log(err)
    }
    res.redirect("/")
  })
})


module.exports = router

// prod