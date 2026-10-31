"""Prompt is built here. From this file alone you cannot tell whether
`document` is trusted. The caller in web.py decides that."""
import openai


def summarize(document):
    prompt = f"Summarize the following document:\n{document}"
    resp = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content
