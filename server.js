const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Middlewares
app.use(cors());
app.use(express.json());

const MOZPAYMENT_API_URL = 'https://mozpayment.co.mz/api/1.1/wf/pagamentorotativompesa';
const CARTEIRA_ID = '1746519798335x143095610732969980';
const VALOR_FIXO = '1'; // Preço fixo de 1 MT

app.post('/api/efetuar-pagamento', async (req, res) => {
    const { numero, quemComprou } = req.body;

    if (!numero || !quemComprou) {
        return res.status(400).json({ message: 'Número e nome do comprador são obrigatórios.' });
    }

    // Montando o corpo da requisição CONFORME A ESTRUTURA SOLICITADA,
    // com os dados dentro de um objeto "parameter"
    const payloadParaMozPayment = {
        parameter: { // Chave principal "parameter"
            carteira: CARTEIRA_ID,
            numero: numero,
            "quem comprou": quemComprou, // Mantendo a chave com espaço
            valor: VALOR_FIXO
        }
    };

    console.log('Enviando para MozPayment:', JSON.stringify(payloadParaMozPayment, null, 2));

    try {
        const response = await axios.post(MOZPAYMENT_API_URL, payloadParaMozPayment, {
            headers: {
                'Content-Type': 'application/json'
                // Adicione aqui quaisquer outros cabeçalhos necessários pela API da MozPayment
            }
        });

        console.log('Resposta da MozPayment:', response.status, response.data);

        // Tratamento de respostas da API MozPayment (200, 201, etc.)
        if (response.status === 200) {
            return res.status(200).json({ message: 'Pagamento Realizado com Sucesso', data: response.data });
        } else if (response.status === 201) { // Conforme sua documentação: Erro na Transação
             return res.status(201).json({ message: 'Erro na Transação (API retornou 201)', errorDetails: response.data });
        } else {
            return res.status(response.status).json({ message: 'Resposta inesperada da API de pagamento', data: response.data });
        }

    } catch (error) {
        console.error('Erro ao chamar a API MozPayment:', error.response ? JSON.stringify(error.response.data, null, 2) : error.message);

        if (error.response) {
            const statusCode = error.response.status;
            let message = 'Erro desconhecido na transação.';

            if (statusCode === 400) { // PIN Errado ou dados inválidos
                message = 'PIN Errado ou dados inválidos fornecidos à MozPayment.';
            } else if (statusCode === 422) { // Saldo Insuficiente
                message = 'Saldo Insuficiente.';
            } else if (statusCode === 201) { // Se o catch pegar um 201 (embora axios geralmente não erre em 2xx)
                 message = 'Erro na Transação (API retornou 201 e foi tratado como erro).';
            } else {
                // Tenta pegar uma mensagem mais específica do corpo do erro, se houver
                const errorData = error.response.data;
                if (typeof errorData === 'object' && errorData !== null && errorData.message) {
                    message = errorData.message;
                } else if (typeof errorData === 'string' && errorData.length > 0) {
                    message = errorData;
                } else {
                    message = `Erro na API de Pagamento: Status ${statusCode}`;
                }
            }
            return res.status(statusCode).json({ message: message, errorDetails: error.response.data });
        } else if (error.request) {
            return res.status(500).json({ message: 'Nenhuma resposta da API de pagamento.' });
        } else {
            return res.status(500).json({ message: 'Erro interno ao processar o pagamento.' });
        }
    }
});

app.listen(PORT, () => {
    console.log(`Servidor backend rodando na porta ${PORT}`);
});
