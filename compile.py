#!/usr/bin/env python3

import sys
import operator
from functools import reduce
import collections

import pydot


preamble = '''enum TransitionError {
    InvalidTransition,
}
'''

Transition = collections.namedtuple('Transition', ['name', 'src_state', 'dst_state', 'side'])


def get_states(g):
    subgraph_nodes = map(get_states, g.get_subgraphs())
    subnodes = reduce(operator.or_, subgraph_nodes, set())

    edges = g.get_edges()
    sources = set(e.get_source() for e in edges)
    targets = set(e.get_destination() for e in edges)

    return sources|targets|subnodes


def get_transitions(g, source=None):
    subgraph_nodes = map(lambda s: get_transitions(s, source), g.get_subgraphs())
    sub_transitions = reduce(operator.add, subgraph_nodes, list())

    edges = g.get_edges()

    if source is not None:
        filtered_transitions = [e for e in edges if e.get_source() == source]
    else:
        filtered_transitions = [e for e in edges]

    filtered_transitions = [Transition(
            name=(e.get_taillabel() or e.get_label()),
            src_state=e.get_source(),
            dst_state=e.get_destination(),
            side=edge_side(e))
        for e in filtered_transitions]

    return filtered_transitions + sub_transitions


def edge_side(e):
    color_to_side = {
        'red': 'server',
        'blue': 'client',
        None: 'both',
    }
    return color_to_side[e.get_color()]


def compile_states_to_rust_enum(states):
    state_names = ''.join('    {},\n'.format(s) for s in sorted(states))
    code = '''#[derive(PartialEq)]
enum State {{
{}}}'''.format(state_names)
    return code


def compile_state_transitions_to_rust_enum(state, transitions):
    transition_names = ['    To{dst_state}({name}),\n'.format(**t._asdict()) for t in transitions]
    variants = ''.join(sorted(transition_names))
    code = '''enum {}Transition {{
{}}}'''.format(state, variants)

    return code


def compile_state_transitions_to_rust_impl(state, transitions):
    tmpl = ' '*12+'{state}Transition::To{dst_state}(_) => Ok(State::{dst_state}),\n'
    pattern_match = ''.join(tmpl.format(state=state, **t._asdict())
                            for t in transitions)

    code = '''impl {state}Transition {{
    fn next(self, state: State) -> Result<State, TransitionError> {{
        if state != State::{state} {{
            return Err(TransitionError::InvalidTransition)
        }}

        match self {{
{pattern_match}        }}
    }}
}}'''.format(state=state, pattern_match=pattern_match)

    return code


def compile_transitions_to_rust_enum(transitions):
    structs = ['struct {};\n'.format(t.name) for t in transitions]
    return ''.join(set(structs))

def compile_to_rust(g):
    print(preamble)

    states = get_states(g)
    code = compile_states_to_rust_enum(states)
    print(code)
    print()

    code = compile_transitions_to_rust_enum(get_transitions(g))
    print(code)
    print()

    for s in states:
        transitions = get_transitions(g, s)
        print(compile_state_transitions_to_rust_enum(s, transitions))
        print(compile_state_transitions_to_rust_impl(s, transitions))
        print()


if __name__ == '__main__':
    input_data = sys.stdin.read()

    (g,) = pydot.graph_from_dot_data(input_data)
    compile_to_rust(g)

