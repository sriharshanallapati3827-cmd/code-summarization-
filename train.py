import os
import torch
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM, Trainer, TrainingArguments
from datasets import load_dataset

from pdg_extractor import extract_pdg_context


def prepare_dataset(sample_limit=5000):
    """
    Loads CodeSearchNet Python dataset and converts it into
    PDG + Code → Summary format.
    """

    print("Loading CodeSearchNet Python dataset...")

    dataset = load_dataset("code_search_net", "python", split="train")

    # Limit dataset size for faster training
    dataset = dataset.select(range(sample_limit))

    inputs = []
    targets = []

    for item in dataset:
        # Support different dataset column formats
        code = item.get("code", item.get("func_code_string"))
        summary = item.get("docstring", item.get("func_documentation_string"))

        # Skip samples with missing data
        if not code or not summary:
            continue

        try:
            pdg = extract_pdg_context(code)

            prompt = f"Summarize Code using PDG.\nPDG Info:\n{pdg}\nCode:\n{code}"

            inputs.append(prompt)
            targets.append(summary)

        except Exception:
            continue

    from datasets import Dataset
    return Dataset.from_dict({"input_text": inputs, "target_text": targets})


def tokenize_data(example, tokenizer, max_input_length=512, max_target_length=64):

    inputs = tokenizer(
        example["input_text"],
        max_length=max_input_length,
        truncation=True,
        padding="max_length"
    )

    labels = tokenizer(
        example["target_text"],
        max_length=max_target_length,
        truncation=True,
        padding="max_length"
    )

    inputs["labels"] = labels["input_ids"]

    return inputs


def train_model():

    model_name = "Salesforce/codet5p-220m"

    print(f"Loading tokenizer and model: {model_name}")

    tokenizer = AutoTokenizer.from_pretrained(
    model_name,
    use_fast=False,
    trust_remote_code=True
)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_name)

    print("Preparing dataset with PDG extraction...")

    # Reduced sample_limit to 1000 to prevent GPU crashes
    dataset = prepare_dataset(sample_limit=1000)

    tokenized_dataset = dataset.map(
        lambda x: tokenize_data(x, tokenizer),
        batched=True,
        remove_columns=["input_text", "target_text"]
    )

    # Split dataset
    split_dataset = tokenized_dataset.train_test_split(test_size=0.1)

    train_dataset = split_dataset["train"]
    eval_dataset = split_dataset["test"]

    training_args = TrainingArguments(
        output_dir="./model_output",
        eval_strategy="epoch",  # evaluation_strategy is deprecated
        learning_rate=2e-5,
        per_device_train_batch_size=2,
        per_device_eval_batch_size=2,
        num_train_epochs=1,  # Reduced from 3 to 1 to speed up training
        weight_decay=0.01,
        save_total_limit=1,
        logging_steps=50,
        fp16=True  # Added fp16 for speed and reduced GPU memory usage
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        tokenizer=tokenizer,
    )

    print("Starting training with CodeSearchNet + PDG...")

    trainer.train()

    print("Saving fine-tuned model...")

    trainer.save_model("./fine_tuned_codet5")
    tokenizer.save_pretrained("./fine_tuned_codet5")

    print("Training complete!")


if __name__ == "__main__":
    train_model()