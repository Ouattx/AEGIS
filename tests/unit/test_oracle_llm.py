from __future__ import annotations

from types import SimpleNamespace

import pytest

from aegis.oracle import llm as llm_mod
from aegis.oracle.llm import DEFAULT_LLM_MODEL, AnthropicLLM, LLMClient, configured_model, llm_from_env


class FakeMessages:
    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        if isinstance(self.behaviour, Exception):
            raise self.behaviour
        return self.behaviour


def fake_client(behaviour):
    return SimpleNamespace(messages=FakeMessages(behaviour))


def response(text="hello", blocks=None):
    blocks = blocks if blocks is not None else [SimpleNamespace(type="text", text=text)]
    return SimpleNamespace(content=blocks, usage=SimpleNamespace(input_tokens=11, output_tokens=7),
                           model="served-model")


def test_default_model_constant_and_env_override(monkeypatch):
    assert DEFAULT_LLM_MODEL == "claude-sonnet-5-5"
    monkeypatch.delenv("AEGIS_LLM_MODEL", raising=False)
    assert configured_model() == DEFAULT_LLM_MODEL
    monkeypatch.setenv("AEGIS_LLM_MODEL", "custom-model")
    assert configured_model() == "custom-model"
    assert AnthropicLLM(client=fake_client(response())).model == "custom-model"


def test_complete_success(monkeypatch):
    monkeypatch.delenv("AEGIS_LLM_MODEL", raising=False)
    client = fake_client(response(blocks=[SimpleNamespace(type="text", text="part1 "),
                                          SimpleNamespace(type="thinking", text="hidden"),
                                          SimpleNamespace(type="text", text="part2")]))
    llm = AnthropicLLM(client=client)
    assert isinstance(llm, LLMClient)
    out = llm.complete(system="sys", messages=[{"role": "user", "content": "u"}], max_tokens=50)
    assert out is not None and out.text == "part1 part2"
    assert (out.input_tokens, out.output_tokens, out.model) == (11, 7, "served-model")
    kw = client.messages.kwargs
    assert kw["model"] == DEFAULT_LLM_MODEL and kw["system"] == "sys" and kw["max_tokens"] == 50


@pytest.mark.parametrize("behaviour", [RuntimeError("boom"), TimeoutError(), response(text="   "),
                                       response(blocks=[])])
def test_complete_failures_return_none(behaviour):
    llm = AnthropicLLM(client=fake_client(behaviour))
    assert llm.complete(system="s", messages=[{"role": "user", "content": "u"}], max_tokens=5) is None


def test_no_api_key_means_no_llm(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert llm_from_env() is None
    assert AnthropicLLM().complete(system="s", messages=[], max_tokens=5) is None


def test_llm_from_env_with_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    client = llm_from_env()
    assert isinstance(client, AnthropicLLM)


def test_missing_sdk_disables_llm(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_anthropic(name, *a, **k):
        if name == "anthropic":
            raise ImportError("not installed")
        return real_import(name, *a, **k)

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    monkeypatch.setattr(builtins, "__import__", no_anthropic)
    assert llm_mod.llm_from_env() is None
    assert AnthropicLLM().complete(system="s", messages=[], max_tokens=5) is None
