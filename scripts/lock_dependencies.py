"""Lock the installed project dependency closure, not the entire Conda environment."""
from importlib import metadata
from pathlib import Path
import tomllib
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def main():
    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / 'pyproject.toml').read_text(encoding='utf-8'))['project']
    queue = list(project['dependencies'])
    queue.extend(project['optional-dependencies']['test'])
    queue.extend(project['optional-dependencies']['dev'])
    extras, versions = {}, {}
    while queue:
        requirement = Requirement(queue.pop(0))
        if requirement.marker and not requirement.marker.evaluate({'extra': ''}):
            continue
        name = canonicalize_name(requirement.name)
        contexts = set(requirement.extras) | {''}
        new = contexts - extras.get(name, set())
        distribution = metadata.distribution(requirement.name)
        if distribution.version not in requirement.specifier:
            raise ValueError(f'Installed version does not satisfy {requirement}')
        if not new:
            continue
        versions[name] = distribution.version
        extras[name] = extras.get(name, set()) | contexts
        for value in distribution.requires or []:
            dependency = Requirement(value)
            if not dependency.marker or any(dependency.marker.evaluate({'extra': extra}) for extra in new):
                # Marker already evaluated against the parent extra context.
                dependency.marker = None
                queue.append(str(dependency))
    text = '# Project + test + LangGraph development dependencies; generated on Linux Conda base.\n'
    text += '# Python 3.13; regenerate for a different platform/Python version.\n'
    text += '\n'.join(f'{name}=={versions[name]}' for name in sorted(versions)) + '\n'
    (root / 'requirements.lock').write_text(text, encoding='utf-8')
    print('Locked project distributions:', len(versions))


if __name__ == '__main__':
    main()
