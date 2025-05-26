const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// carteira fica aqui, oculta do frontend
const carteira = '1746519798335x143095610732969980';

app.post('/pagamento', async (req, res) => {
  const { numero, quemComprou, valor } = req.body;

  try {
    const response = await axios.post('https://mozpayment.co.mz/api/1.1/wf/pagamentorotativoemola', {
      carteira,
      numero,
      'quem comprou': quemComprou,
      valor,
    });

    if (response.data.success === 'yes') {
      const whatsappLink = `https://wa.me/258${numero}?text=Obrigado+pelo+pagamento,+${encodeURIComponent(quemComprou)}!+Estamos+à+disposi%C3%A7%C3%A3o.`;
      res.json({ success: true, whatsappLink });
    } else {
      res.json({ success: false, message: 'Pagamento reprovado' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erro no servidor', error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
