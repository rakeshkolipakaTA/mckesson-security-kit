import pickle

import torch
from langchain_community.vectorstores import FAISS
from langchain_experimental.tools import PythonREPLTool
from transformers import AutoModelForCausalLM


def load_everything(path, embeddings):
    model = AutoModelForCausalLM.from_pretrained("someorg/custom-llm", trust_remote_code=True)     # unpinned revision + remote code
    weights = torch.load(path + "/model.bin")                                                       # pickle-based, no weights_only
    store = FAISS.load_local(path + "/index", embeddings, allow_dangerous_deserialization=True)     # pickle deserialisation
    cfg = pickle.load(open(path + "/config.pkl", "rb"))
    return model, weights, store, cfg, PythonREPLTool()                                             # REPL tool = code execution
