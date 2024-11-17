const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const sendgridMail = require('@sendgrid/mail');
const bcrypt = require('bcryptjs');
const app = express();
const port = 3000;

sendgridMail.setApiKey('');

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'db-ana',
});

db.connect((err) => {
  if (err) {
    console.error('Erro ao conectar ao banco de dados:', err);
    return;
  }
  console.log('Conectado ao banco de dados MySQL');

  const createTableUsuarios = `
    CREATE TABLE IF NOT EXISTS usuarios (
      id INT AUTO_INCREMENT PRIMARY KEY,
      nome VARCHAR(100) NOT NULL,
      dataNascimento DATE NOT NULL,
      cidade VARCHAR(100) NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      senha VARCHAR(255) NOT NULL
    );
  `;

  const createTableVerificacoes = `
    CREATE TABLE IF NOT EXISTS verificacoes (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(100) UNIQUE NOT NULL,
      codigo INT NOT NULL,
      dataEnvio TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `;
  
  db.query(createTableUsuarios, (err) => {
    if (err) console.error('Erro ao criar tabela usuarios:', err);
  });

  db.query(createTableVerificacoes, (err) => {
    if (err) console.error('Erro ao criar tabela verificacoes:', err);
  });
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.post('/enviar-codigo', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).send('E-mail é obrigatório');
  }

  db.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, result) => {
    if (err) {
      console.error('Erro ao verificar e-mail no registro:', err);
      return res.status(500).send('Erro ao verificar e-mail');
    }

    if (result.length > 0) {
      return res.status(400).send('E-mail já registrado. Não é possível enviar código de verificação.');
    }

    const codigo = Math.floor(100000 + Math.random() * 900000);

    db.query('INSERT INTO verificacoes (email, codigo) VALUES (?, ?)', [email, codigo], (err) => {
      if (err) {
        console.error('Erro ao salvar código de verificação:', err);
        return res.status(500).send('Erro ao salvar código de verificação');
      }
    });

    const msg = {
      to: email,
      from: 'anamnesia.suporte@gmail.com',
      subject: 'Código de Verificação',
      text: `Seu código de verificação é: ${codigo}`,
      html: `<strong>Seu código de verificação é: ${codigo}</strong>`,
    };

    sendgridMail
      .send(msg)
      .then(() => {
        res.status(200).send('Código de verificação enviado');
      })
      .catch((error) => {
        console.error('Erro ao enviar o código de verificação:', error);
        res.status(500).send('Erro ao enviar o código');
      });
  });
});

app.post('/verificar-codigo', (req, res) => {
  const { email, codigoInformado } = req.body;

  if (!email || !codigoInformado) {
    return res.status(400).send('E-mail e código de verificação são obrigatórios');
  }

  db.query('SELECT codigo FROM verificacoes WHERE email = ? ORDER BY dataEnvio DESC LIMIT 1', [email], (err, result) => {
    if (err) {
      console.error('Erro ao verificar o código:', err);
      return res.status(500).send('Erro ao verificar o código');
    }

    if (result.length === 0 || result[0].codigo !== parseInt(codigoInformado)) {
      return res.status(400).send('Código inválido');
    }

    res.status(200).send('Código verificado com sucesso');
  });
});

app.post('/registrar', (req, res) => {
  const { nome, dataNascimento, cidade, email, senha, codigoInformado } = req.body;

  if (!nome || !dataNascimento || !cidade || !email || !senha || !codigoInformado) {
    return res.status(400).send('Todos os campos são obrigatórios');
  }

  db.query('SELECT codigo FROM verificacoes WHERE email = ? ORDER BY dataEnvio DESC LIMIT 1', [email], (err, result) => {
    if (err) {
      console.error('Erro ao verificar o código:', err);
      return res.status(500).send('Erro ao verificar o código');
    }

    if (result.length === 0 || result[0].codigo !== parseInt(codigoInformado)) {
      return res.status(400).send('Código inválido');
    }

    db.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, result) => {
      if (err) {
        console.error('Erro ao verificar o e-mail:', err);
        return res.status(500).send('Erro ao verificar e-mail');
      }

      if (result.length > 0) {
        return res.status(400).send('E-mail já cadastrado');
      }

      bcrypt.hash(senha, 10, (err, hash) => {
        if (err) {
          console.error('Erro ao criptografar a senha:', err);
          return res.status(500).send('Erro ao criptografar a senha');
        }

        db.query(
          'INSERT INTO usuarios (nome, dataNascimento, cidade, email, senha) VALUES (?, ?, ?, ?, ?)',
          [nome, dataNascimento, cidade, email, hash],
          (err) => {
            if (err) {
              console.error('Erro ao registrar usuário:', err);
              return res.status(500).send('Erro ao registrar usuário');
            }

            res.status(200).send('Usuário registrado com sucesso');
          }
        );
      });
    });
  });
});

app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
