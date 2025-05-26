const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001; // Porta para o backend

// Middlewares
app.use(cors()); // Permite requisições de diferentes origens
app.use(express.json()); // Para parsear o corpo da requisição como JSON

const MOZPAYMENT_API_URL = 'https://mozpayment.co.mz/api/1.1/wf/pagamentorotativompesa';
const CARTEIRA_ID = '1746519798335x143095610732969980';
const VALOR_FIXO = '1'; // Preço fixo de 1 MT

app.post('/api/efetuar-pagamento', async (req, res) => {
    const { numero, quemComprou } = req.body;

    if (!numero || !quemComprou) {
        return res.status(400).json({ message: 'Número e nome do comprador são obrigatórios.' });
    }

    const requestBody = {
        carteira: CARTEIRA_ID,
        numero: numero,
        "quem comprou": quemComprou, // Note a chave com espaço, conforme a API original
        valor: VALOR_FIXO
    };

    console.log('Enviando para MozPayment:', requestBody);

    try {
        // ATENÇÃO: A API da MozPayment espera os parâmetros diretamente no corpo,
        // não aninhados dentro de um objeto "parameter" como no exemplo da sua pergunta.
        // O `.then(function (response) {` no seu exemplo de request body sugere que
        // ele é parte de um código JavaScript e não a estrutura exata do JSON a ser enviado.
        // O corpo do JSON enviado para a API deve ser apenas o objeto com os campos.

        const response = await axios.post(MOZPAYMENT_API_URL, requestBody, {
            headers: {
                'Content-Type': 'application/json'
                // Adicione aqui quaisquer outros cabeçalhos necessários pela API da MozPayment
                // Ex: 'Authorization': 'Bearer SEU_TOKEN_SE_NECESSARIO'
            }
        });

        // A API da MozPayment parece retornar o status HTTP diretamente como indicador do resultado.
        // O corpo da resposta da API pode ou não conter dados adicionais.
        // Vamos assumir que o status da resposta do axios reflete o status da API.

        console.log('Resposta da MozPayment:', response.status, response.data);

        // Retornando o status e a mensagem para o front-end
        // É importante notar que a API da MozPayment usa códigos de status HTTP
        // para indicar sucesso ou falha. Nós vamos repassar isso.
        // A documentação da MozPayment indica:
        // 200 = Pagamento Realizado com Sucesso
        // 201 = Erro na Transação (Isso é incomum, POST bem-sucedido geralmente é 201 para criação ou 200 para processamento)
        // 422 = Saldo Insuficiente
        // 400 = PIN Errado

        // O axios lança um erro para status >= 400, então eles serão pegos no bloco catch.
        // Tratamos o 200 e o 201 (se a API realmente o usar para erro) aqui.

        if (response.status === 200) {
            return res.status(200).json({ message: 'Pagamento Realizado com Sucesso', data: response.data });
        } else if (response.status === 201) { // Se 201 realmente for um erro conforme sua doc
             return res.status(201).json({ message: 'Erro na Transação', errorDetails: response.data });
        } else {
            // Caso a API retorne um status de sucesso inesperado
            return res.status(response.status).json({ message: 'Resposta inesperada da API de pagamento', data: response.data });
        }

    } catch (error) {
        console.error('Erro ao chamar a API MozPayment:', error.response ? error.response.data : error.message);

        if (error.response) {
            // A requisição foi feita e o servidor respondeu com um status code
            // que cai fora do range de 2xx
            const statusCode = error.response.status;
            let message = 'Erro desconhecido na transação.';

            if (statusCode === 400) {
                message = 'PIN Errado ou dados inválidos fornecidos à MozPayment.';
            } else if (statusCode === 422) {
                message = 'Saldo Insuficiente.';
            } else if (statusCode === 201) { // Tratando 201 como erro, conforme a doc
                 message = 'Erro na Transação (API retornou 201).';
            } else {
                message = error.response.data.message || `Erro na API de Pagamento: ${statusCode}`;
            }
            return res.status(statusCode).json({ message: message, errorDetails: error.response.data });
        } else if (error.request) {
            // A requisição foi feita mas nenhuma resposta foi recebida
            return res.status(500).json({ message: 'Nenhuma resposta da API de pagamento.' });
        } else {
            // Algo aconteceu ao configurar a requisição que acionou um erro
            return res.status(500).json({ message: 'Erro interno ao processar o pagamento.' });
        }
    }
});

app.listen(PORT, () => {
    console.log(`Servidor backend rodando na porta ${PORT}`);
});
