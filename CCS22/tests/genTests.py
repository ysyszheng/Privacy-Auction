import argparse
import random

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Generate test parameters.")

  parser.add_argument('--tests', type=int, help="The number of tests to generate.")
  parser.add_argument('--bidders_max', type=int, help="The upper bound for bidders.")
  parser.add_argument('--bitslen_max', type=int, help="The upper bound for bits length.")

  args = parser.parse_args()

  with open('params.txt', 'w') as f:
      for _ in range(args.tests):
          num1 = random.randint(1, args.bidders_max)
          num2 = random.randint(1, args.bitslen_max)
          f.write(f'{num1} {num2}\n')
