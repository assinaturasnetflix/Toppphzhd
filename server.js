const express = require('express');
const fetch = require('node-fetch'); // Ou use o fetch global se estiver no Node.js 18+
const app = express();
const port = 3000; // Você pode escolher outra porta

// Middleware para parsear JSON no corpo das requisições
app.use(express.json());

// Endpoint que o frontend vai chamar
app.post('/pagar', async (req, res) => {
    const { numero, quem_comprou, valor } = req.body;

    // Validação básica dos dados recebidos
    if (!numero || !quem_comprou || !valor) {
        return res.status(400).json({ error: 'Dados incompletos.' });
    }

    const idCarteira = '1746519798335x143095610732969980'; // Seu ID da carteira
    const apiUrl = 'https://mozpayment.co.mz/api/1.1/wf/pagamentorotativoemola';

    const payload = {
        carteira: idCarteira,
        numero: numero,
        'quem comprou': quem_comprou, // Atenção ao nome do parâmetro com espaço
        valor: valor
    };

    console.log('Enviando para MozPayment:', payload);

    try {
        const mozPaymentResponse = await fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                // Adicione quaisquer outros headers necessários pela API da MozPayment (ex: Chave de API, se houver)
            },
            body: JSON.stringify(payload)
        });

        // Verifica se a resposta da MozPayment foi OK (status 2xx)
        if (!mozPaymentResponse.ok) {
            const errorText = await mozPaymentResponse.text();
            console.error('Erro da API MozPayment:', mozPaymentResponse.status, errorText);
            // Tenta parsear como JSON se possível, caso contrário usa o texto do erro
            try {
                const errorJson = JSON.parse(errorText);
                return res.status(mozPaymentResponse.status).json({ error: `Erro da MozPayment: ${errorJson.message || errorText}` });
            } catch (e) {
                return res.status(mozPaymentResponse.status).json({ error: `Erro da MozPayment: ${errorText}` });
            }
        }

        const resultadoPagamento = await mozPaymentResponse.json();
        console.log('Resposta da MozPayment:', resultadoPagamento);

        if (resultadoPagamento.success && resultadoPagamento.success.toLowerCase() === 'yes') {
            // Pagamento aprovado
            const numeroWhatsApp = '258865097696'; // Número para o qual o link do WhatsApp será gerado (com código do país)
            const mensagemWhatsApp = encodeURIComponent('Olá! Adquiri o plano e meu pagamento foi aprovado.'); // Mensagem opcional
            const linkWhatsapp = `https://wa.me/${numeroWhatsApp}?text=${mensagemWhatsApp}`;

            res.json({ linkWhatsapp: linkWhatsapp });
        } else {
            // Pagamento reprovado ou resposta inesperada
            res.status(400).json({ error: resultadoPagamento.message || 'Pagamento reprovado pela MozPayment.' });
        }

    } catch (error) {
        console.error('Erro ao processar pagamento no backend:', error);
        res.status(500).json({ error: 'Erro interno no servidor.' });
    }
});

// Para servir o arquivo HTML do frontend (opcional, pode ser servido separadamente)
// Coloque o arquivo HTML (ex: index.html) na mesma pasta ou numa pasta 'public'
// const path = require('path');
// app.use(express.static(path.join(__dirname))); // Serve arquivos da raiz
// app.get('/', (req, res) => {
//    res.sendFile(path.join(__dirname, 'index.html'));
// });


app.listen(port, () => {
    console.log(`Servidor backend rodando em http://localhost:${port}`);
});
