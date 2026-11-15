"""Fine-tuning LoRA du modèle analyste — à exécuter sur un GPU GRATUIT (Google Colab T4 / Kaggle),
PAS sur le PC (CPU seul = impraticable). Le modèle résultant tourne ensuite en CPU via Ollama.

Étapes :
 1. Générer le dataset localement :  python ai/dataset/build_dataset.py --n 1500
 2. Ouvrir un notebook Colab (Exécution > Modifier le type d'exécution > GPU T4)
 3. Copier ce script cellule par cellule (séparateurs « # %% »), téléverser train.jsonl
 4. Télécharger le .gguf produit, le placer à côté de ai/Modelfile, modifier la ligne FROM,
    puis : ollama create adsentry-analyst -f ai/Modelfile

⚠ Le modèle de base ici DOIT être le même que celui utilisé dans Ollama.
⚠ Vérifier les noms exacts des modèles Unsloth sur https://huggingface.co/unsloth au moment
  de l'entraînement (les API Unsloth/TRL évoluent vite : ajuster si une erreur apparaît).
⚠ N'envoyer sur Colab QUE des données synthétiques / de lab — jamais un vrai snapshot client.
"""

# %% 1. Installation
# !pip install -q unsloth trl datasets

# %% 2. Chargement du modèle de base en 4 bits
from unsloth import FastLanguageModel  # noqa: E402

BASE_MODEL = "unsloth/Qwen3.5-4B"  # à aligner avec le FROM d'ai/Modelfile
MAX_SEQ = 8192

model, tokenizer = FastLanguageModel.from_pretrained(model_name=BASE_MODEL, max_seq_length=MAX_SEQ, load_in_4bit=True)
model = FastLanguageModel.get_peft_model(
    model,
    r=16,
    lora_alpha=32,
    lora_dropout=0.0,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    use_gradient_checkpointing="unsloth",
)

# %% 3. Dataset (format chat -> texte via le template du modèle)
from datasets import load_dataset  # noqa: E402

ds = load_dataset("json", data_files="train.jsonl", split="train").train_test_split(test_size=0.05, seed=42)


def to_text(batch):
    return {"text": [tokenizer.apply_chat_template(m, tokenize=False) for m in batch["messages"]]}


ds = ds.map(to_text, batched=True, remove_columns=["messages"])

# %% 4. Entraînement
from trl import SFTConfig, SFTTrainer  # noqa: E402

trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=ds["train"],
    eval_dataset=ds["test"],
    args=SFTConfig(
        dataset_text_field="text",
        max_seq_length=MAX_SEQ,
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        num_train_epochs=2,
        learning_rate=2e-4,
        warmup_ratio=0.05,
        logging_steps=10,
        eval_strategy="steps",
        eval_steps=100,
        output_dir="outputs",
        seed=42,
    ),
)
trainer.train()

# %% 5. Export GGUF fusionné (quantifié pour CPU) -> à importer dans Ollama
model.save_pretrained_gguf("adsentry-analyst", tokenizer, quantization_method="q4_k_m")
# Le fichier .gguf se trouve dans ./adsentry-analyst/ : le télécharger depuis le panneau Fichiers.
