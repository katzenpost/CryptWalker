import VersoBlog
import CryptLib

open Verso Genre Blog Site Syntax
open Verso.Output Html Template Theme

def repo := "https://github.com/katzenpost/cryptlib"

def logo : Html := {{
  <svg class="logo" viewBox="0 0 32 32" aria-hidden="true">
    <rect x="6" y="14" width="20" height="14" rx="3"/>
    <path d="M11 14 V10 a5 5 0 0 1 10 0 V14" fill="none" stroke-width="3"/>
    <circle cx="16" cy="21" r="2.2" class="keyhole"/>
  </svg>
}}

def primary (version : String) : Template := do
  let posts := match (← param? "posts") with
    | none => Html.empty
    | some html => {{ <ul class="posts">{{html}}</ul> }}
  return {{
    <html lang="en">
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <meta name="color-scheme" content="light dark"/>
        <title>{{s!"{← param (α := String) "title"} · Cryptlib"}}</title>
        {{← builtinHeader}}
        <link rel="icon" href="static/favicon.svg"/>
        <link rel="stylesheet" href="static/style.css"/>
      </head>
      <body>
        <header class="site">
          <a class="brand" href=".">{{logo}}<span>"Cryptlib"</span></a>
          <nav>
            <ol>
              {{← dirLinks (← read).site}}
              <li><a href="api/">"API"</a></li>
              <li><a href={{repo}}>"GitHub"</a></li>
            </ol>
          </nav>
        </header>
        <main>
          {{← param "content"}}
          {{posts}}
        </main>
        <footer class="site">
          <p>
            "Cryptlib is free software under the AGPLv3, part of the "
            <a href="https://katzenpost.network/">"Katzenpost"</a>
            " project. "
            "Documentation for " <a href={{repo}}>{{version}}</a> "."
          </p>
        </footer>
      </body>
    </html>
  }}

def front : Template := do
  pure {{
    <section class="hero">
      {{logo}}
      <h1>"Cryptlib"</h1>
      <p class="tagline">"Cryptography for Lean 4, where a primitive's type says what must be proved about it."</p>
      <p class="buttons">
        <a class="button" href="overview/">"Overview"</a>
        <a class="button secondary" href="api/">"API reference"</a>
      </p>
    </section>
    <article class="front">{{← param "content"}}</article>
  }}

def theme (version : String) : Theme :=
  { Theme.default with primaryTemplate := primary version }
  |>.override #[] ⟨front, id⟩

def cryptlib : Site := site CryptLib.Front /
  static "static" ← "static"
  "overview" CryptLib.Overview
  "primitives" CryptLib.Primitives
  "getting-started" CryptLib.GettingStarted
  "blog" CryptLib.Blog with
    CryptLib.Blog.Hello

def main (args : List String) : IO UInt32 := do
  let version := (← IO.getEnv "CRYPTLIB_VERSION").getD "main"
  blogMain (theme version) cryptlib (options := args)
