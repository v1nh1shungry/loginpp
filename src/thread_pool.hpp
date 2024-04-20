#pragma once
#ifndef THREAD_POOL_HPP
#define THREAD_POOL_HPP

#include "noncopyable.hpp"

#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <type_traits>
#include <vector>

class ThreadPool final : public Noncopyable {
public:
  explicit ThreadPool(std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) {
      workers_.emplace_back([this]() {
        while (true) {
          std::function<void()> task;
          {
            std::unique_lock lock{this->mutex_};
            this->cv_.wait(lock, [this]() {
              return this->stop_ or not this->tasks_.empty();
            });
            if (this->stop_ and this->tasks_.empty())
              return;
            task = std::move(this->tasks_.front());
            this->tasks_.pop();
          }
        }
      });
    }
  }

  ~ThreadPool() {
    {
      std::unique_lock lock{mutex_};
      stop_ = true;
    }
    cv_.notify_all();
    for (auto &w : workers_) {
      w.join();
    }
  }

  template <class F, class... Args>
  auto submit(F &&func,
              Args &&...args) -> std::future<std::result_of_t<F(Args...)>> {
    using return_type = std::result_of_t<F(Args...)>;
    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(func), std::forward<Args>(args)...));
    std::future<return_type> res = task->get_future();
    {
      std::unique_lock lock{mutex_};
      tasks_.emplace([task]() { (*task)(); });
    }
    cv_.notify_one();
    return res;
  }

private:
  std::vector<std::thread> workers_{};
  std::queue<std::function<void()>> tasks_{};
  std::mutex mutex_{};
  std::condition_variable cv_{};
  bool stop_ = false;
};

#endif // !THREAD_POOL_HPP
